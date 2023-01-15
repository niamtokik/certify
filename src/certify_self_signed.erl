%%%===================================================================
%%% @doc
%%% @end
%%%===================================================================
-module(certify_self_signed).
-export([new/0, new/1]).
-include_lib("public_key/include/public_key.hrl").

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
new() ->
    new([]).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
new(_Args) ->
    RsaPrivateKey = public_key:generate_key({rsa, 2048, 65537}),
    % RsaPrivateKeyEntry = public_key:pem_entry_encode('RSAPrivateKey', RsaPrivateKey),
    % RsaPrivateKeyPem = public_key:pem_encode([RsaPrivateKeyEntry]),    
    CertificateVersion = v3,
    <<SerialNumber:(20*8)>> = crypto:strong_rand_bytes(20),
    IssuerUniqueId = asn1_NOVALUE,
    SubjectUniqueId = asn1_NOVALUE,
    Issuer = default_issuer(),
    SignatureAlgorithm = default_signature_algorithm(),
    RsaPublicKey =  default_rsa_public_key(RsaPrivateKey),
    RsaPublicKeyAlgorithm = default_public_key_algorithm(),
    PublicKeyInfo = default_public_key_info(RsaPublicKeyAlgorithm, RsaPublicKey),
    RsaPublicKeyLength = length(erlang:integer_to_list(RsaPublicKey#'RSAPublicKey'.modulus, 2)),
    RsaPublicKeyBitstring = <<(RsaPublicKey#'RSAPublicKey'.modulus):RsaPublicKeyLength>>,
    SubjectKeySignature = crypto:hash(sha, RsaPublicKeyBitstring),        
    SubjectKeyIdentifier = default_subject_key_identifier(SubjectKeySignature),
    AuthorityKeyIdentifier = default_authority_key_identifier(SubjectKeySignature),
    BasicConstraints = default_basic_constraints(),
    Extensions = [SubjectKeyIdentifier, AuthorityKeyIdentifier, BasicConstraints],
    Validity = default_validity("20221231000000Z", "20231231000000Z"),
    RawCertificate = #'OTPTBSCertificate'{
                        version = CertificateVersion,
                        signature = SignatureAlgorithm,
                        serialNumber = SerialNumber,
                        issuer = Issuer,
                        issuerUniqueID = IssuerUniqueId,
                        validity = Validity,
                        subject = Issuer,
                        subjectUniqueID = SubjectUniqueId,
                        subjectPublicKeyInfo = PublicKeyInfo,
                        extensions = Extensions
                       },
    CertificateDer = public_key:pkix_sign(RawCertificate, RsaPrivateKey),
    Certificate = public_key:der_decode('Certificate', CertificateDer),
    {ok, RsaPrivateKey, Certificate}.

default_country_name() ->
    [#'AttributeTypeAndValue'{
        type = 'OTP-PUB-KEY':'id-at-countryName'(),
        value = "SE" 
    }].

default_common_name() ->
    [#'AttributeTypeAndValue'{ 
        type = 'OTP-PUB-KEY':'id-at-commonName'(),
        value = {printableString, "localhost"}
    }].

default_common_name_wildcard() ->
    [#'AttributeTypeAndValue'{ 
        type = 'OTP-PUB-KEY':'id-at-commonName'(),
        value = {printableString, "*.localhost"}
       }].

default_organization_name() ->
    [#'AttributeTypeAndValue'{
        type = 'OTP-PUB-KEY':'id-at-organizationName'(),
        value = {printableString, "localhost"}
       }].

default_issuer() ->
    CountryName = default_country_name(),
    CommonName = default_common_name(),
    CommonNameWildcard = default_common_name_wildcard(),
    OrganizationName = default_organization_name(),
    {rdnSequence, [CountryName, CommonName, CommonNameWildcard, OrganizationName]}.

default_signature_algorithm() ->
    #'SignatureAlgorithm'{
       algorithm  = 'OTP-PUB-KEY':sha256WithRSAEncryption(),
       parameters = 'NULL'
      }.

default_rsa_public_key(RsaPrivateKey = #'RSAPrivateKey'{}) ->
    #'RSAPublicKey'{
       modulus = RsaPrivateKey#'RSAPrivateKey'.modulus, 
       publicExponent = RsaPrivateKey#'RSAPrivateKey'.publicExponent
      }.

default_public_key_algorithm() ->
    #'PublicKeyAlgorithm'{
       algorithm = 'OTP-PUB-KEY':rsaEncryption(),
       parameters ='NULL'
      }.

default_public_key_info(RsaPublicKeyAlgorithm, RsaPublicKey) ->
    #'OTPSubjectPublicKeyInfo'{
       algorithm = RsaPublicKeyAlgorithm,
       subjectPublicKey = RsaPublicKey
      }.

default_subject_key_identifier(SubjectKeySignature) ->
    #'Extension'{
       extnID = 'OTP-PUB-KEY':'id-ce-subjectKeyIdentifier'(),
       extnValue = SubjectKeySignature,
       critical = false 
      }.

default_authority_key_identifier(SubjectKeySignature) ->
    #'Extension'{
       extnID = 'OTP-PUB-KEY':'id-ce-authorityKeyIdentifier'(),
       extnValue = #'AuthorityKeyIdentifier'{
                      keyIdentifier = SubjectKeySignature,
                      authorityCertIssuer = asn1_NOVALUE,
                      authorityCertSerialNumber = asn1_NOVALUE
                     },
       critical = false 
      }.

default_basic_constraints() ->
    #'Extension'{
       extnID = 'OTP-PUB-KEY':'id-ce-basicConstraints'(),
       extnValue = #'BasicConstraints'{ cA = true },
       critical = true
      }.

default_validity(Before, After) ->
    #'Validity'{
       notBefore = {generalTime, Before},
       notAfter =  {generalTime, After}
      }.
