use Apache2;
use Apache::Test;
use Apache::TestRequest;
use Apache::TestUtil;

plan tests => 1;

my $config = Apache::Test::config();

my $url =  '?1!200!!20040426T101359Z!1082974432-5140-6!' . Apache::TestRequest::hostport($config)  .  '!rb368!pwd!!36000!!1!kchH9VoCacqznIWXLRzWBaBjElL3Eqf97JGDBpTPHx1N-WXqEYtbcYsmaU8c-Q70pN5jYAY0B46IocJaa4w-AyUEG4AQRQ5emiodsM79aAVV8RH6tGyhuc025qm8kPhQ1v33aaATBbGdbhFjLcBm.9DKigZpc334DZyqB6Nf2DQ_';

t_debug($url);

my $response = GET $url;

t_debug($response->code);

ok $response->code != 200;
