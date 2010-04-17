package Catalyst::TraitFor::Controller::Login::SSLCert;
use MooseX::MethodAttributes::Role;
use MooseX::Types::Moose qw/ HashRef ArrayRef ClassName Object Str /;
use namespace::autoclean;

# ABSTRACT: SSL Client Cert Login!

has 'sslcert_host' => (
	isa => "Str",
	is  => "rw",
);

has 'sslcert_realm' => (
    isa => "Str",
    is  => "rw",
    required => 1,
);

sub login_sslcert : Chained('/') PathPart('login/sslcert') Args(0) {
    my ($self, $c) = @_;

	my $uri          = $c->uri_for($c->action);

	if(!($uri->host eq $self->sslcert_host ) && $self->sslcert_host )
	{
		$uri->host($self->sslcert_host);
		$uri->scheme("https");
		$c->res->redirect($uri);
		$c->detach();
	}

	if(!($uri->scheme eq "https"))
	{
        $uri->scheme("https");
        $c->res->redirect($uri);
        $c->detach();
	}

    if(!$c->engine->env->{"SSL_CLIENT_VERIFY"} eq "SUCCESS")
    {
        $c->stash( 'error_msg' => "SSL Client Cert Login failed! CLIENT CERT NOT SUCCESSFULLY VERIFIED!");
        $c->detach;
    }

    if($c->authenticate({}, $self->sslcert_realm))
    {
        $c->stash( 'success_msg' => "SSL Client Cert Login Successfull!" );
    }
    else
    {
        $c->stash( 'error_msg'   => sprintf("Sorry but SSL Client Cert Login failed! Your DN was \"%s\"!", $c->engine->env->{'SSL_CLIENT_S_DN'}));
    }

	$c->stash( 'template' => 'index.tt');
}

1;

=head1 NAME

Catalyst::TraitFor::Controller::Login::SSLCert

=head1 DESCRIPTION

Simple controller role for SSL Client Cert Login.

Please set the Config keys "sslcert_realm", for the Realm which Allows SSL Login, "sslcert_host", for the 
ssl client cert enabled host, for the Controller::Login!

=head1 ACTIONS

=head2 login_sslcert : Chained('/') PathPart('login/sslcert') Args(0)

Logs the user in via SSL Client Cert!

=head1 SEE ALSO

=over

=item L<CatalystX::SimpleLogin>

=back

=head1 AUTHORS

See L<CatalystX::SimpleLogin> for authors.

=head1 LICENSE

See L<CatalystX::SimpleLogin> for license.

=cut
