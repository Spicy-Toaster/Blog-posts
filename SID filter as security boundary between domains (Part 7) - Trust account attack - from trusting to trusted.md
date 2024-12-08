Originally published on https://blog.improsec.com April 8th 2022.
https://blog.improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-7-trust-account-attack-from-trusting-to-trusted
_Authors: Jonas Bülow Knudsen, Martin Sohn Christensen, Tobias Thorbjørn Munch Torp


This is the final post of a seven part series. Check out [part 1 Kerberos authentication explained](https://improsec.com/tech-blog/o83i79jgzk65bbwn1fwib1ela0rl2d) for links to the others.

During writing of this series, we have read many articles regarding trusts. One of such is _hamj0y_’s [Not A Security Boundary: Breaking Forest Trusts](https://blog.harmj0y.net/redteaming/not-a-security-boundary-breaking-forest-trusts/) which states that “_administrators from one forest can in fact compromise resources in a forest that it shares a two-way interforest trust with_”. This compromise is achieved by abusing unconstrained delegation and the printer bug, as we described in [Part 2](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-2-known-ad-attacks-from-child-to-parent) of this series.

The same harmj0y article states that the attack was not possible over a one-way trust: “_We tested the one-way interforest trust scenario, where FORESTB.xLOCAL –trusts–> FORESTA.LOCAL, but we were unable to get the attack working in either direction_”.

However, using a simple technique we found another way to compromise resources of the trusted (FORESTA) domain.

In short, if an attacker has administrative access to FORESTB which trusts FORESTA, the attacker can obtain the credentials for a _trust account_ located in FORESTA. This account is a member of Domain Users in FORESTA through its Primary Group. As we see too often, Domain Users membership is all that is necessary to identify and use other techniques and attack paths to become Domain Admin.

This technique is not limited to forest trust but works over any domain/forest one-way trust in the direction trusting -> trusted. The trust protections (SID filtering, disabled SID history, and disabled TGT delegation) do not mitigate the technique.

We have included possible mitigations and detections in this post.

# Content

- Trust account attack
    
- Demonstration
    
    - The arena
        
    - Trust account attack demonstration
        
    - Trust account cleartext password
        
- Attack limitations
    
- Microsoft Security Response Center’s response
    
- Mitigation and detection
    
    - Cycling inter-domain trust account secret
        
- Part 7 conclusion
    

# Trust account attack

When an Active Directory domain or forest trust is set up from a domain _B_ to a domain _A_ (_B_ trusts _A_), a _trust account_ is created in domain _A_, named _B$_. Kerberos _trust keys,_ derived from the trust account’s password, are used for encrypting inter-realm TGTs, when users of domain A request service tickets for services in domain B. (_See_ [_Part 1_](https://improsec.com/tech-blog/o83i79jgzk65bbwn1fwib1ela0rl2d) _for explanation of Kerberos authentication between domains and inter-realm TGTs_).

It has been known for years that it is possible to obtain the trust keys (B$’ cleartext credentials and Kerberos keys) from any of the DCs in either of the domains with administrative privileges using tools like Mimikatz. This is no surprise, as the secret must be stored in both domains for encrypting inter-realm tickets in domain A and decrypting in domain B.

The risk is because of trust account B$ is enabled, B$’s Primary Group is Domain Users of domain A, any permission granted to Domain Users applies to B$, and it is possible to use B$’s credentials to authenticate against domain A with Kerberos to obtain Kerberos tickets, which are accepted by various services in domain A.

Essentially, you can “escalate” from Domain Admins in one domain to Domain Users in another domain, even in another forest, in the same direction as the trust relationship:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/61a0233f-edd8-40b6-b6ae-8592a29875bd/Picture3.png)

The Domain Users group is not privileged by default but will often be granted permissions that are not intended for users of another domain/forest. As the [Microsoft documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#domain-users) explains “_The Domain Users group includes all user accounts in a domain_”, which is why users of another domain (potentially a non-trusted domain) are not granted this membership by default.

Even default permissions granted to Domain Users are in some cases enough to compromise the domain the group belongs to using techniques such as:

- AD enumeration / attack path discovery
    
- Network share enumeration
    
- Creation of DNS records
    
- Join computers to the domain
    
- Exploit certificate templates
    
- Kerberoasting
    
- and much more...
    

# Demonstration

To demonstrate the attack, we will show how a trusting (low privileged) domain (ext.local) in one forest is able to compromise a trusted (high privileged) domain (root.local) in another forest across one-way forest trust.

## The arena

The EXT DC (EXT-DC-01.ext.local), and outbound trust details for root.local:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/044650ff-4fdc-4109-b133-8961b850ac5e/01.png)

The ROOT DC (ROOT-DC-01.root.local), and inbound trust details for ext.local:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/9fe2bda4-6d8f-4188-9a7d-72b706fbd43f/02.png)

The trust account (EXT$.root.local) for the trust relationship from ext.local to root.local:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/5e5c5159-3c47-41ce-9784-e4f85cca2097/03.png)

A one-way forest trust is thus created between root.local and ext.local, where ext.local trusts root.local but not opposite, in other words root.local has one-way incoming trust, and ext.local has one-way outgoing trust.

## Trust account attack demonstration

We will demonstrate how a Domain Admin in ext.local can obtain a session as the trust account root.local\EXT$, and then Kerberoast root.local\svc_SQL-01 which is a member of Domain Admins in root.local.

Because root.local does not trust ext.local, querying root.local from ext.local is not possible with any ext.local user or group membership:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/d0150cd7-bfec-49b8-9a0c-46a202eff043/04.png)

We cannot request root.local service tickets for Kerberoasting either.

What we can do instead as ext.local\Administrator on EXT-DC-01.ext.local, is dump the outgoing trust keys using Mimikatz:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/f4baaa00-be30-4a94-8f6b-f5e88797704f/05.png)

We get [ Out ] and [ Out-1 ], these are respectively [the TDO’s (Trusted Domain Object) ‘NewPassword’ attribute and ‘OldPassword’ attribute](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc773178(v=ws.10)#tdo-passwords), which are the keys used for inter-realm TGTs.

The TDO is not EXT$, but a ‘trustedDomain’ object type in ext.local: “_CN=root.local,CN=System,DC=ext,DC=local_”. In root.local a corresponding TDO exist: “_CN=ext.local,CN=System,DC=root,DC=local_”. On both sides, the trust keys are the same. TDOs exist in both domains, but a trust account is only created in the trusted domain for a one-way trust.

The ‘NewPassword’ and ‘OldPassword’ are identical because the trust in our lab is recently created, and the trust key has not changed yet. The key is cycled automatically every ~30 days, as described in [MS-ADTS] section 6.1.6.9.6.1.

As described in Part 1 [_Kerberos authentication explained_](https://improsec.com/tech-blog/o83i79jgzk65bbwn1fwib1ela0rl2d) section _AD Trust_, the trust keys (stored in TDOs) are derived from the trust account’s password. In fact, the ‘NewPassword’ cleartext trust key is the current password of the trust account, and the ‘OldPassword’ cleartext trust key is the previous password (or the current password in certain circumstances).

This means, we have root.local\EXT$’s current cleartext password and Kerberos secret key stored as trust keys in ext.local’s TDO for root.local “_CN=root.local,CN=System,DC=ext,DC=local_”. The root.local\EXT$ Kerberos AES secret keys are on identical to the AES trust keys as a different salt is used, but the RC4 keys are the same. Therefore, we can use the RC4 trust key dumped from ext.local as to authenticate as root.local\EXT$ against root.local.

With the RC4 trust key, we request a TGT from root.local using:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/82387803-75a2-4d16-9cf9-8b6bd98945f0/06.png)

Using this ticket, we can obtain a valid service ticket to ROOT-DC-01.root.local, query the service account, and Kerberoast it:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/d93f0ce3-7300-4e26-8fa9-349c23a7e69a/07.png)

The password hash can now be cracked to obtain Domain Admin of root.local.

We can confirm that we indeed got at LDAP service as EXT$ (and an extra TGT):

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/39104288-f653-438d-914d-5bc29c5bf590/08.png)

## Trust account cleartext password

Mimikatz also dumps the trust key in cleartext as hexadecimal, consider again the same dump:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/f88ad8c9-eeb5-4fe9-a02c-5649bdae695c/Picture14.png)

The cleartext password can be obtained by converting the  [ CLEAR ] output marked in red from hexadecimal and removing null bytes ‘\x00’:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/a0e6ee83-533f-43df-be6a-09c8fc208b4b/66QIFwtC5n.png)

Sometimes when creating a trust relationship, a password must be typed in by the user for the trust. In this demonstration, the key is the original trust password and therefore human readable. As the key cycles (30 days), the cleartext will not be human-readable but technically still usable.

The cleartext password can be used to perform regular authentication as the trust account, an alternative to requesting a TGT using the Kerberos secret key of the trust account. Here, querying root.local from ext.local for members of Domain Admins:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/67bfcb17-7246-4711-a377-dde32edbe753/Picture15.png)

# Attack limitations

The following logins are not possible with a trust account:

**Non-Network logins**

Some logon types are not allowed, such as RUNAS, console login, and RDP login (Interactive and RemoteInteractive logon types).

The only logon type which has been confirmed to be accepted is Network. NewCredentials, Batch, Service, and NetworkCleartext logon types have not been assessed.

**NTLM authentication**

NTLM logins are prevented and return a “STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT” code with the message “_The account used is an interdomain trust account. Use your global user account or local user account to access this server_”. Here is an example of denied access:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/a61b5778-3907-488b-b4cb-82d72d200d8c/Picture16.png)

The failed NTLM authentication will generate a logon failed Security event in the trusted domain (root.local):

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/1612089f-b15e-4da9-bb8c-97b924c8a25c/Picture17.png)

# Microsoft Security Response Center’s response

The trust account attack was reported to Microsoft who responded to it as low severity and that they will consider mitigation in the next full release of Windows:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/44acc932-3761-457e-8c82-97d5d4adb4cf/Picture18.png)

# Mitigation and detection

We have not tested mitigations for this attack but implementing the following should prevent it. However, as it is not tested, we cannot say for certain what the consequences of doing this in a production environment is and it should therefore be applied carefully as it may break stuff.

UPDATE: Disabling the trust account or removing its Domain Users membership is not possible. Thanks to [@ipcdollar1](https://twitter.com/ipcdollar1).

Mitigation of this attack may be one of the following:

- Implement Authentication Policies
    
- Deny log on for the trust account with User Rights Assignments
    
- Adding the trust account of the trusted domain to Protected Users
    
    - May not mitigate in all environments. Will deny the use of RC4 in the Kerberos pre-authentication process. RC4 is by default the only supported encryption type for the TDO user account.
        
    - Add all TDOs to Protected Users: Get-ADUser -Filter 'sAMAccountType -eq 805306370' | % {Add-ADGroupMember "Protected Users" $_}
        

The following could also mitigate it, but operations are not possible as they throw the error “Operation Failed. Error code 0x5. Access Denied. 00000005: SecErr: DSID-031A11EF, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0”.

- Change the Primary Group of the trust account to a less privileged group than Domain Users
    
- Disable the trust account
    

We have searched multiple production AD forests for activity of the trust account (both in Event Logs and LastLogon property) and have not found it to ever perform logins. We would appreciate if others continued with mitigation research**.**

Detection of this attack is possible by monitoring any logon attempts by the trust account in the trusted (root.local) domain.

In the demonstrated attack a TGT request will be sent, it is possible to detect TGT requests in the trusted domain’s (root.local) security log relating to the trust account name:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/6f6feec8-94ce-438c-a1cc-b078a69241b2/Picture19.png)

And any successful logon events from the trust account:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/b6196ee8-b997-43fe-b377-60db9fe9f4d2/Picture20.png)

The ‘Ticket Encryption Type’ will be 0x17, known as RC4_HMAC_MD5. This is because Rubeus is called with the ‘/rc4’ parameter. Other encryption types are possible, but not in default configurations since the trust account’s ‘msDS-SupportedEncryptionTypes’ attribute will be blank which means only RC4 is allowed.

## Cycling inter-domain trust account secret

Upon compromise of the trusting domain (ext.local), the trust key should be cycled manually to prevent persistence, but only after gaining trust in the trusting domain (ext.local) again.

For this Microsoft’s procedure [_Resetting a trust password on one side of the trust_](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-reset-trust) can be used. In the demonstrated forest we ran the following from the trusted domain (root.local):

netdom trust **root.local** /domain:**ext.local** /resetOneSide /passwordT:**7EPj5yZhHwa7UShB** /userO:**administrator** /passwordO:*

Then ran the following from the trusting domain’s (ext.local) PDC emulator:

netdom trust **ext.local** /domain:**root.local** /resetOneSide /passwordT:**7EPj5yZhHwa7UShB** /userO:**administrator** /passwordO:*

The trust account attack with any of the old keys is thereafter prevented. Without cycling the key, persistence would last for 60 days (two 30-day trust key reset cycles). Prorogation to all domain controllers should happen within a day.

As described in part 1 [_Kerberos authentication explained_](https://improsec.com/tech-blog/o83i79jgzk65bbwn1fwib1ela0rl2d) section _AD Trust,_ a single password change of the trust account will not invalidate the current inter-realm TGTs, as there is fall-back to the previous trust keys (TDO’s OldPassword). However, ‘netdom trust /resetOneSide’ overwrites both the current and previous trust keys, as stated by Microsoft: “_Run this command only once (unlike the netdom resetpwd command) because it automatically resets the password twice_”. The command resets only EXT$ password once, but both the TDO object’s ‘OldPassword’ and ‘NewPassword’ attributes are overwritten with same keys derived from the new password. This is reflected when we dump EXT$’s credentials after ‘netdom trust /resetOneSide’ is executed, where the previous password hashes are marked in red:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/38bda1ed-5793-4452-a09e-4e610d9a08b2/Picture21.png)

This could have resulted in [NTLM network authentication still accepting the previous password for up to 60 minutes after a password change](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/new-setting-modifies-ntlm-network-authentication#change-the-lifetime-period-of-an-old-password), but as mentioned under limitations: NTLM authentication is not allowed for the trust account and we therefore do not find a second password change of EXT$ necessary.

# Part 7 conclusion

We have demonstrated how incoming trust (domain or forest) allows attackers to gain Domain User access and constitute a risk for the trusted domain.

In an environment built on the [Active Directory Red Forest Design aka Enhanced Security Administrative Environment (ESAE)](https://social.technet.microsoft.com/wiki/contents/articles/37509.active-directory-red-forest-design-aka-enhanced-security-administrative-environment-esae.aspx), a design where one-way outgoing forest trust is established from production forests to an administrative forest (red forest), this attack will allow an attacker who have compromised a production forest to gain Domain Users access in the red forest. Similarly, if a one-way forest trust exists from a DMZ forest towards a production forest, the attack could be used to jump from DMZ further into the IT environment.