package Furl::S3;

use strict;
use warnings;
use Class::Accessor::Lite;
use Furl::HTTP qw(HEADERS_AS_HASHREF);
use HTTP::Date;
use Data::Dumper;
use XML::LibXML;
use XML::LibXML::XPathContext;
use Furl::S3::Error;
use Params::Validate qw(:types validate_with validate_pos);
use URI::Escape qw(uri_escape_utf8);
use Carp ();
use AWS::Signature4;
use HTTP::Request;
use URI;
use URI::QueryParam;
use Digest::SHA qw(sha256_hex);
use Scalar::Util;

Class::Accessor::Lite->mk_accessors(qw(secure furl endpoint region signer));

our $VERSION = '0.03';
our $DEFAULT_ENDPOINT = 's3.%s.amazonaws.com';
our $XMLNS = 'http://s3.amazonaws.com/doc/2006-03-01/';

sub new {
    my $class = shift;
    validate_with( 
        params => \@_, 
        spec => {
            aws_access_key_id => 1,
            aws_secret_access_key => 1,
            region => 1,
        },
        allow_extra => 1,
    );
    my %args = @_;
    my $aws_access_key_id = delete $args{aws_access_key_id};
    my $aws_secret_access_key = delete $args{aws_secret_access_key};
    my $region = delete $args{region};
    Carp::croak("aws_access_key_id and aws_secret_access_key and region are mandatory") unless $aws_access_key_id && $aws_secret_access_key && $region;
    my $secure = delete $args{secure} || '0';
    my $endpoint = delete $args{endpoint} || sprintf($DEFAULT_ENDPOINT, $region);
    my $furl = Furl::HTTP->new( 
        agent => '$class/'. $VERSION,
        %args,
        header_format => HEADERS_AS_HASHREF,
    );

    my $signer = AWS::Signature4->new(
        -access_key => $aws_access_key_id,
        -secret_key => $aws_secret_access_key,
    );

    my $self = bless {
        endpoint => $endpoint,
        secure => $secure,
        signer => $signer,
        region => $region,
        furl => $furl,
    }, $class;
    $self;
}

sub _trim {
    my $str = shift;
    $str =~ s/^\s+//;
    $str =~ s/\s+$//;
    $str;
}

sub _remove_quote {
    my $str = shift;
    $str =~ s/^"//;
    $str =~ s/"$//;
    $str;
}

sub _boolean {
    my $str = shift;
    if ( $str eq 'false' ) {
        return 0;
    }
    return 1;
}

# http://docs.amazonwebservices.com/AmazonS3/2006-03-01/dev/index.html?BucketRestrictions.html
sub validate_bucket {
    my $bucket = shift;
    return 
        ($bucket =~ qr/^[a-z0-9][a-z0-9\._-]{2,254}$/) && 
            ($bucket !~ /^\d+\.\d+\.\d+\.\d+$/); # IP Address
}

sub is_dns_style {
    my $bucket = shift;
    return unless validate_bucket( $bucket );
    return if $bucket =~ /_/;
    return if length($bucket) < 3 || length($bucket) > 63;
    return if $bucket =~ /\.\./;
    my @parts = split /\./, $bucket;
    for my $p(@parts) {
        return if $p =~ /-$/
    }
    return 1;
}

sub resource {
    my( $self, $bucket, $key, $subresource ) = @_;
    my $resource = $bucket;
    $resource = '/'. $resource unless $resource =~ m{^/};
    if ( defined $key ) {
        $key = _normalize_key($key);
        $resource = join '/', $resource, $key;
    }
    if ( $subresource ) {
        $resource .= '?'. $subresource;
    }
    $resource =~ s{//}{/}g;
    $resource;
}

sub _path_query {
    my( $self, $path, $q ) = @_;
    $path = '/'. $path unless $path =~ m{^/};
    my $qs = ref($q) eq 'HASH' ? 
        join('&', map { $_. '='. uri_escape_utf8( $q->{$_} ) } keys %{$q}) : $q;
    $path .= '?'. $qs if $qs;
    $path;
}

sub host_and_path_query {
    my( $self, $bucket, $key, $params ) = @_;
    my($host, $path_query);
    $key = _normalize_key($key);
    if ( is_dns_style($bucket) ) {
        $host = join '.', $bucket, $self->endpoint;
        $path_query = $self->_path_query( $key, $params );
    }
    else {
        $host = $self->endpoint;
        $path_query = $self->_path_query( join('/', $bucket, $key), $params );
    }
    $path_query =~ s{//}{/}g;
    return ($host, $path_query);
}

sub request {
    my $self = shift;
    my( $method, $bucket, $key, $params, $headers, $furl_options ) = @_;
    validate_pos( @_, 1, 1, 
                  { type => SCALAR | UNDEF, optional => 1 },
                  { type => HASHREF | UNDEF | SCALAR , optional => 1, }, 
                  { type => HASHREF | UNDEF , optional => 1, },
                  { type => HASHREF | UNDEF , optional => 1, }, );
    $self->clear_error;
    $key ||= '';
    $params ||= +{};
    $headers ||= +{};
    $furl_options ||= +{};

    my %h;
    while (my($key, $val) = each %{$headers}) {
        $key =~ s/_/-/g; # content_type => content-type
        $h{lc($key)} = $val
    }
    if ( !$h{'expires'} && !$h{'date'} ) {
        $h{'date'} = time2str(time);
    }

    my( $host, $path_query ) = 
        $self->host_and_path_query( $bucket, $key, $params );
    my %res;
    my @h = %h;

    my $u = URI->new(sprintf('%s://%s', ($self->secure ? 'https' : 'http'), $host));
    $u->path_query($path_query);

    my $content_is_fh = Scalar::Util::openhandle($furl_options->{content});

    my $req = HTTP::Request->new(
        $method,
        $u->as_string,
        \@h,
        $content_is_fh ? undef : $furl_options->{content},
    );

    # filehandle uses "UNSIGNED-PRELOAD"
    my $payload_digest = $content_is_fh ? 'UNSIGNED-PAYLOAD' : sha256_hex($req->content);
    $req->header('X-Amz-Content-Sha256' => $payload_digest);
    $self->signer->sign($req, $self->region, $payload_digest);

    # stolen from Furl
    my $req_headers = $req->headers;
    $req_headers->remove_header('Host'); # suppress duplicate Host header
    my $signed_headers = +[
        map {
            my $k = $_;
            map { ( $k => $_ ) } $req_headers->header($_);
        } $req_headers->header_field_names
    ];

    @res{qw(ver code msg headers body)} = $self->furl->request(
        url     => $req->uri,
        method  => $req->method,
        content => $content_is_fh ? $furl_options->{content} : $req->content,
        headers => $signed_headers,
        %{$furl_options},
    );
    return \%res;
}

sub signed_url {
    my $self = shift;
    validate_pos(@_, 1, 1, +{ regexp => qr/^\d+$/, });
    my( $bucket, $key, $expires ) = @_;
    my $expires_in = $expires - time;

    # imitate "aws s3 presign"
    my $u = URI->new(sprintf('%s://%s', ($self->secure ? 'https' : 'http'), $self->endpoint));
    $u->path_query($self->_path_query( join('/', $bucket, $key), +{}));
    $self->signer->signed_url($u, $expires_in);
}


sub _create_xpc {
    my( $self, $string ) = @_;
    my $xml = XML::LibXML->new;
    my $doc = $xml->parse_string( $string );
    my $xpc = XML::LibXML::XPathContext->new( $doc );
    $xpc->registerNs('s3' => $XMLNS);
    return $xpc;
}

sub list_buckets {
    my $self = shift;
    my $res = $self->request( 'GET', '/' );
    unless ( _http_is_success($res->{code}) ) {
        return $self->error( $res );
    }
    my $xpc = $self->_create_xpc( $res->{body} );
    my @buckets;
    for my $node($xpc->findnodes('/s3:ListAllMyBucketsResult/s3:Buckets/s3:Bucket')) {
        my $name = $xpc->findvalue('./s3:Name', $node);
        my $creation_date = $xpc->findvalue('./s3:CreationDate', $node);
        push @buckets, +{
            name => $name,
            creation_date => $creation_date,
        };
    } 
    return +{
        buckets => \@buckets,
        owner => +{
            id => $xpc->findvalue('/s3:ListAllMyBucketsResult/s3:Owner/s3:ID'),
            display_name => $xpc->findvalue('/s3:ListAllMyBucketsResult/s3:Owner/s3:DisplayName'),
        },
    }
}

sub create_bucket {
    my $self = shift;
    my( $bucket, $headers ) = @_;
    validate_pos( @_, 
                  { type => SCALAR, 
                    callbacks => { bucket_name => \&validate_bucket } },
                  { type => HASHREF, optional => 1, } );

    my $data;
    # ref: https://docs.aws.amazon.com/general/latest/gr/rande.html
    # ...If you use a region other than the US East (N. Virginia) endpoint to create a bucket, you must set the LocationConstraint bucket parameter to the same region....
    if ($self->region ne 'us-east-1') {
        $data = "<CreateBucketConfiguration><LocationConstraint>".
                $self->region.
                "</LocationConstraint></CreateBucketConfiguration>";
    }

    my $res = $self->request( 'PUT', $bucket, undef, undef, $headers, +{ content => $data });
    unless ( _http_is_success($res->{code}) ) {
        return $self->error( $res );
    }
    return 1;
}

sub delete_bucket {
    my $self = shift;
    my( $bucket ) = @_;
    validate_pos( @_, 1 );
    my $res = $self->request( 'DELETE', $bucket );
    unless ( _http_is_success($res->{code}) ) {
        return $self->error( $res );
    }
    return 1;
}

sub list_objects {
    my $self = shift;
    my( $bucket, $params ) = @_;
    validate_pos( @_, 1, { type => HASHREF, optional => 1 });
    my $res = $self->request( 'GET', $bucket, undef, $params );
    unless ( _http_is_success($res->{code}) ) {
        return $self->error( $res );
    }
    my $xpc = $self->_create_xpc( $res->{body} );
    my @contents;
    for my $node($xpc->findnodes('/s3:ListBucketResult/s3:Contents')) {
        push @contents, +{
            key => $xpc->findvalue('./s3:Key', $node),
            etag => _remove_quote( $xpc->findvalue('./s3:ETag', $node) ),
            storage_class => $xpc->findvalue('./s3:StorageClass', $node),
            last_modified => $xpc->findvalue('./s3:LastModified', $node),
            size => $xpc->findvalue('./s3:Size', $node),
            owner => +{
                id => $xpc->findvalue('./s3:Owner/s3:ID', $node),
                display_name => $xpc->findvalue('./s3:Owner/s3:DisplayName', $node),
            },
        };
    }
    my @common_prefixes;
    for my $node($xpc->findnodes('/s3:ListBucketResult/s3:CommonPrefixes')) {
        push @common_prefixes, +{
            prefix => $xpc->findvalue('./s3:Prefix', $node),
        };
    }
    return +{
        name => $xpc->findvalue('/s3:ListBucketResult/s3:Name'),
        is_truncated => _boolean($xpc->findvalue('/s3:ListBucketResult/s3:IsTruncated')),
        delimiter => $xpc->findvalue('/s3:ListBucketResult/s3:Delimiter'),
        max_keys => $xpc->findvalue('/s3:ListBucketResult/s3:MaxKeys'),
        marker => $xpc->findvalue('/s3:ListBucketResult/s3:Marker'),
        contents => \@contents,
        common_prefixes => \@common_prefixes,
    };
}

sub create_object {
    my $self = shift;
    my( $bucket, $key, $content, $headers ) = @_;
    validate_pos( @_, 1, 1, 
                  { type => HANDLE | SCALAR }, 
                  { type => HASHREF, optional => 1 } );
    my $res = $self->request( 'PUT', $bucket, $key, undef, $headers, +{ content => $content });
    unless ( _http_is_success($res->{code}) ) {
        return $self->error( $res );
    }
    return 1;
}

sub create_object_from_file {
    my $self = shift;
    my( $bucket, $key, $filename, $headers ) = @_;
    validate_pos( @_, 1, 1, 1,
                  { type => HASHREF, optional => 1 } );

    $headers ||= {};
    my $has_ct = 0;
    for my $key( keys %{$headers} ) {
        if (lc($key) =~ qr/^(content_type|content-type)$/) {
            $has_ct = 1;
            last ;
        }
    }
    unless ( $has_ct ) {
        require File::Type;
        my $ft = File::Type->new;
        my $content_type = $ft->checktype_filename( $filename );
        $headers->{'content_type'} = $content_type;
    }
    open my $fh, '<', $filename or die "$!: $filename";
    $self->create_object( $bucket, $key, $fh, $headers )
}

sub copy_object {
    my $self = shift;
    my( $source_bucket, $source_key, $dest_bucket, $dest_key, $headers ) = @_;
    validate_pos( @_, 
                  1, 1, 1, 
                  { type => SCALAR | UNDEF, optional => 1 },
                  { type => HASHREF, optional => 1} );
    $headers ||= +{};
    my $source = $self->resource( $source_bucket, $source_key );
    $self->create_object( $dest_bucket, $dest_key, '', {
        %{$headers},
        'x-amz-copy-source' => $source,
    });
}

sub _normalize_response {
    my( $self, $res, $is_head ) = @_;
    my %res;
    while (my($k, $v) = each %{$res->{headers}}) {
        $res{$k} = $v;
    }
    # remove etag's double quote.
    if ( my $etag = $res{'etag'} ) {
        $res{etag} = _remove_quote( $etag );
    }
    # make aliases
    $res{content_length} = $res{'content-length'};
    $res{content_type} = $res{'content-type'};
    $res{last_modified} = $res{'last-modified'};
    unless ( $is_head ) {
        $res{content} = $res->{body};
    }
    return \%res;
}


sub get_object {
    my $self = shift;
    my( $bucket, $key, $headers, $furl_options ) = @_;
    validate_pos( @_, 1, 1, 
                  { type => HASHREF, optional => 1 },
                  { type => HASHREF, optional => 1 }, );
    my $res = $self->request( 'GET', $bucket, $key, undef, $headers, $furl_options );
    unless ( _http_is_success($res->{code}) ) {
        return $self->error( $res );
    }
    $self->_normalize_response( $res );
}

sub get_object_to_file {
    my $self = shift;
    my( $bucket, $key, $filename ) = @_;
    validate_pos( @_, 1, 1, 1 );
    open my $fh, '>', $filename or die "$!: $filename";
    $self->get_object( $bucket, $key, {}, {
        write_file => $fh,
    });
}

sub head_object {
    my $self = shift;
    my( $bucket, $key, $headers ) = @_;
    validate_pos( @_, 1, 1, { type => HASHREF, optional => 1 } );
    my $res = $self->request( 'HEAD', $bucket, $key, undef, $headers );
    unless ( _http_is_success($res->{code}) ) {
        return $self->error( $res );
    }
    $self->_normalize_response( $res, 1 );
}

sub delete_object {
    my $self = shift;
    my( $bucket, $key ) = @_;
    validate_pos( @_, 1, 1 );
    my $res = $self->request( 'DELETE', $bucket, $key );
    unless ( _http_is_success($res->{code}) ) {
        return $self->error( $res );
    }
    return 1;
}

sub clear_error {
    my $self = shift;
    delete $self->{_error};
}

sub error {
    my $self = shift;
    if ( @_ ) {
        my $error = Furl::S3::Error->new( $_[0] );
        $self->{_error} = $error;
        return ;
    }
    $self->{_error};
}

sub _normalize_key {
    my $key = shift;
    join '/', map { _uri_escape($_) } split /\//, $key;
}

sub _http_is_success {
    $_[0] >= 200 && $_[0] < 300;
}

sub _uri_escape {
    uri_escape_utf8($_[0], '^A-Za-z0-9\._-');
}
1;


__END__

=head1 NAME

Furl::S3 - Furl based S3 client library.

=head1 SYNOPSIS

  use Furl::S3;

  my $s3 = Furl::S3->new( 
      aws_access_key_id => '...', 
      aws_secret_access_key => '...',
  );
  $s3->create_bucket($bucket) or die $s3->error;

  my $res = $s3->list_objects($bucket) or die $s3->error;
  for my $obj(@{$res->{contents}}) {
      printf "%s\n", $obj->{key};
  }

=head1 DESCRIPTION

This module uses L<Furl> lightweight HTTP client library and provides very simple interfaces to Amazon Simple Storage Service (Amazon S3)

for more details. see Amazon S3's developer guide and API References.

http://docs.amazonwebservices.com/AmazonS3/2006-03-01/dev/

http://docs.amazonwebservices.com/AmazonS3/2006-03-01/API/

=head1 METHODS

=head2 Furl::S3->new( %args )

returns a new Furl::S3 object.

I<%args> are below.

=over

=item aws_access_key_id 

AWS Access Key ID

=item aws_secret_access_key

AWS Secret Access Key.

=item secure

boolean flag. uses SSL connection or not.

=item endpoint

S3 endpoint hostname. the default value is I<s3.amazonaws.com>

other parmeters are passed to Furl->new. see L<Furl> documents.

=back

=head2 request($method, $bucket, [ $key ], [ \%params ], [ \%headers ], [ \%furl_options ]);

sends signed request. returns a Furl::Response object.

=over

=item $method

HTTP Request Method.

=item $bucket

bucket name.

=item $key

key of object.

=item \%params

request parameters.

=item \%headers

HTTP headers.

=item \%furl_options

arguments of $furl->request.

=back

=head2 list_buckets

list all buckets.
returns a HASH-REF

  {
      'owner' => {
        'id' => '...',
        'display_name' => '..'
      },
      'buckets' => [
          {
              'creation_date' => '2010-11-30T00:00:00.000Z',
              'name' => 'Your bucket name'
          },
          #...
      ]
  }

=head2 create_bucket($bucket, [ \%headers ])

create new bucket.
returns a boolean value. 

=head2 delete_bucket($bucket);

delete bucket.
returns a boolean value.

=head2 list_objects($bucket, [ \%params ])

list all objects in specified bucket.
returna a HASH-REF 


  {
      'marker' => '',
      'common_prefixes' => [],
      'max_keys' => '10',
      'contents' => [
          {
               'owner' => {
                   'id' => '..'
                   'display_name' => '...'
               },
               'etag' => 'xxx',
               'storage_class' => 'STANDARD',
               'last_modified' => '2010-12-01T00:00:00.000Z',
               'size' => '10000',
               'key' => 'foo/bar/baz.txt'
          },
          #... 
      ],
      'name' => 'Your bucket name',
      'delimiter' => '',
      'is_truncated' => 1
   }

\%params are below.
see Amazon S3 documents for detail.

http://docs.amazonwebservices.com/AmazonS3/2006-03-01/API/index.html?RESTBucketGET.html

=over

=item delimiter

=item marker

=item max-keys

=item prefix

=back

=head2 create_object($bucket, $key, $content, [ \%headers ]);

create new object.
$content is passed to Furl. so you can specify scalar value or FileHandle object.

you can set any request headers. example is below.

  open my $fh, '<', 'image.jpg' or die $!;
  $s3->create_object('you-bucket', 'public.jpg', $fh, {
      content_type => 'image/jpg',
      'x-amz-acl' => 'public-read',
  });
  close $fh;

=head2 get_object($bucket, $key, [ \%headers, \%furl_options ]);

get object.

\%furl_options are passed to Furl->request method. so you can use write_code or write_file to handle response.

returns a HASH-REF.

  {
      content => $content, 
      content_length => '..',
      etag => '...',
      content_type => '...',
      last_modified => '...',
      'x-amz-meta-foo' => 'metadata'
  }

=head2 get_object_to_file($bucket, $key, $filename);

get object and write to file.
returns a boolean value.

=head2 head_object($bucket, $key, [ \%headers ]);

get object's metadata.
returns a HASH-REF

  {
      content_length => '..',
      etag => '...',
      content_type => '...',
      last_modified => '...',
      'x-amz-meta-foo' => 'metadata'
  }

=head2 delete_object($bucket, $key);

delete object.
returns a boolean value.

=head2 copy_object($source_bucket, $source_key, $dest_bucket, $dest_key, [ \%headers ]);

copy object.
return a boolean value.

=head1 AUTHOR

Tomohiro Ikebe E<lt>ikebe {at} shebang.jpE<gt>

=head1 SEE ALSO

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
