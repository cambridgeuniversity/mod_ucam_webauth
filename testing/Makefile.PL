#require Apache2;
require Apache::TestMM;
require Apache::TestRunPerl;

Apache::TestMM->import(qw(test clean));
Apache::TestMM::filter_args();

Apache::TestRunPerl->generate_script();	

