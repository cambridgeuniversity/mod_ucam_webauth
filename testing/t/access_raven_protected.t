use Apache2;
use Apache::Test;
use Apache::TestRequest;
use Apache::TestUtil;

plan tests => 1;

my $response = GET '/index.html';
t_debug($response->as_string);
ok $response->code == 200;
