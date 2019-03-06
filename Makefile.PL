use inc::Module::Install;
use Module::Install::AuthorTests;
#use Module::Install::ReadmeMarkdownFromPod;
name 'Furl-S3';
all_from 'lib/Furl/S3.pm';
#readme_markdown_from 'lib/Furl/S3.pm';

# requires '';

requires 'Furl' => '0.38';
requires 'Class::Accessor::Lite';
requires 'HTTP::Date';
requires 'XML::LibXML';
requires 'XML::LibXML::XPathContext';
requires 'Params::Validate';
requires 'File::Type';
requires 'URI::Escape';
requires 'AWS::Signature4';
requires 'HTTP::Request';

tests 't/*.t';
author_tests 'xt';

build_requires 'Test::More';

auto_include;
WriteAll;
