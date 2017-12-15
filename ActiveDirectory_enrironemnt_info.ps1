#ACTIVE DIRECTORY ENVIRONMENT INFO

Import-Module ActiveDirectory

$show = $true

$ADINFO = @{}

$ADINFO.RootDSE = $(Get-ADRootDSE)
$ADINFO.ForestInformation = $(Get-ADForest)
$ADINFO.DomainInformation = $(Get-ADDomain)
$ADINFO.DomainControllers = $(Get-ADDomainController -Filter *)
$ADINFO.DomainTrusts = (Get-ADTrust -Filter *)
$ADINFO.Sites = $(Get-ADReplicationSite -Filter *)
$ADINFO.DefaultPassWordPoLicy = $(Get-ADDefaultDomainPasswordPolicy)
$ADINFO.AuthenticationPolicySilos = $(Get-ADAuthenticationPolicySilo -Filter 'Name -like "*AuthenticationPolicySilo*"')
$ADINFO.AuthenticationPolicies = $(Get-ADAuthenticationPolicy -LDAPFilter '(name=AuthenticationPolicy*)')
$ADINFO.CentralAccessPolicies = $(Get-ADCentralAccessPolicy -Filter *)
$ADINFO.CentralAccessRules = $(Get-ADCentralAccessRule -Filter *)
$ADINFO.ClaimTransformPolicies = $(Get-ADClaimTransformPolicy -Filter *)
$ADINFO.ClaimTypes = $(Get-ADClaimType -Filter *)
$ADINFO.DomainAdministrators =$( Get-ADGroup -Identity $('{0}-512' -f (Get-ADDomain).domainSID) | Get-ADGroupMember -Recursive)
$ADINFO.OrganizationalUnits = $(Get-ADOrganizationalUnit -Filter *)
$ADINFO.OptionalFeatures =  $(Get-ADOptionalFeature -Filter *)
$ADINFO.Subnets = $(Get-ADReplicationSubnet -Filter *)
$ADINFO.SiteLinks = $(Get-ADReplicationSiteLink -Filter *)
$ADINFO.LDAPDNS = $(Resolve-DnsName -Name "_ldap._tcp.$((Get-ADDomain).DNSRoot)" -Type srv)
$ADINFO.KerberosDNS = $(Resolve-DnsName -Name "_kerberos._tcp.$((Get-ADDomain).DNSRoot)" -Type srv)

If ($Show -eq $True) {
    Return $ADSnapshot
}
