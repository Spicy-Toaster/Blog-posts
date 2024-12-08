Originally published on https://blog.improsec.com April 1st 2022. 
https://blog.improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-3-sid-filtering-explained
_Authors: Jonas Bülow Knudsen, Martin Sohn Christensen, Tobias Thorbjørn Munch Torp


This blog post is part three of a seven-part series.

This blog post will explain SID filtering for an intra-forest AD trust and demonstrate how SID filtering prevents the attacks shown in part 2: [_Known AD attacks – from child to parent_](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-2-known-ad-attacks-from-child-to-parent). It’s not necessary to read part 2 first, but it is recommended.

# Content

- SID filtering vs inter-realm golden ticket
    
- SID filtering vs unconstrained delegation and printer bug
    
- SID filtering and universal groups
    
- SIDs not filtered
    
- Part 3 conclusion
    

# Background knowledge

As stated in part 1, SID history is used when migrating AD security principles (e.g., users and groups) from an old domain to a new one. Principals will get a new SID in the new domain and lose their old SID. Because permissions in AD are granted to a principal’s SID, migrated principals will lose their access to resources in the old domain. The attribute [SID-History](https://docs.microsoft.com/en-us/windows/win32/adschema/a-sidhistory) is therefore used to let principals keep their access even when migrated. The attribute holds the security principal's SID from the previous domains the security principal belonged to.

However, the SID history is only necessary when migrated users must have access to resources in their previous domain(s). If no user has this requirement, SID filtering can[[JBK1]](https://blog.improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-3-sid-filtering-explained#_msocom_1)  be applied. SID filtering or ‘quarantine’ as the action of the filter is named, ensures that incoming authentication requests received from a trusted domain will be stripped from SIDs not belonging to the trusted domain. So, when sending an inter-realm TGT from a child domain containing a SID from the parent domain in ExtraSids, the KDC of the parent domain will filter out the parent SID in the service ticket to the child domain user. Thereby preventing the [SID-History Injection](https://attack.mitre.org/techniques/T1134/005/) attack.

SID filtering can be set using the built-in program Netdom in Windows: “netdom trust /d:CHILD ROOT /Quarantine:YES”, here enabled on the trust from the ROOT domain to the CHILD domain. The command must be executed on a DC by a Domain Admin. Removing the “Yes” value from the quarantine parameter reveals the status, which will return “SID filtering is enabled for this trust” if quarantine is enabled:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/6a5b0fc4-36a5-42bd-bb33-2f9bb8f91a05/image1.png)

A reboot is required for the change to take effect. Note that the Netdom command /EnableSIDhistory:[Yes/No] is for forest trust only, and does not work for intra-forest trust like child-parent trust.

With SID filtering enabled, the trust relation object’s binary ”trustAttributes” attribute will have its third last digit set to 1, meaning that [TRUST_ATTRIBUTE_ QUARANTINED_DOMAIN (TAQD) is enabled for the object](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c).

SID filtering is enabled by default for forest trust and external trust but disabled for inside the forest. Enabling it can cause things to break as users might lose access rights, which is why it should be tested carefully before applying it.

# SID filtering vs inter-realm golden ticket

In part 2 we demonstrated how forged Kerberos tickets with Enterprise Admins SID in ExtraSids gave us Enterprise Admin access to the parent domain, either by creating a golden ticket with the child domain krbtgt secret key (Method #1) or creating an inter-realm TGT with the trust key (Method #2). Now, let’s test Method #1 with SID filtering enabled on the trust from the parent domain to the child domain.

We create a golden ticket with Enterprise Admins SID in ExtraSids:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/9135fad1-3c61-48c2-9da2-9fdc44737b1a/image2.png)

When we try to access the parent domain DC, we get access denied:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/1d90b868-c708-4909-a97c-41ce70646a7c/image3.png)

Let’s take a look inside the Kerberos tickets to understand why. We have four Kerberos tickets in our session:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/889adae5-6037-4cb3-8eb1-47c129a8e5e4/image4.png)

Ticket #2 is the golden ticket created by us. When we attempted to connect to the parent DC, #0, #1, and #3 were generated. #0 is identical to #2, but with Cache Flags changed from PRIMARY to DELEGATION and with the ticket flag ‘initial’ removed and added ‘forwarded’ and ‘name_canonicalize’. Ticket #0 is created because #2 does not have the properties required to request an inter-realm TGT. Ticket #1 is the inter-realm TGT encrypted with the trust key, which is sent to the parent KDC. At last, ticket #3 is the service ticket for the CIFS service on the parent DC, encrypted with Kerberos secret key of the parent DC account (ROOT-DC-01$).

We dump all four tickets to disk using Mimikatz: sekurlsa::tickets /export

The decryption of the golden ticket reveals that the Enterprise Admins SID indeed was added to the ticket:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/dbf30345-b1ba-4082-bd2c-57d63bc00e05/image5.png)

Enterprise Admins SID persists through ticket #0, and is also present in ticket #1 (inter-realm TGT):

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/a94ccf2c-447d-41a2-a06a-0fa7d4594650/image6.png)

But! SID filtering makes the parent KDC filter the Enterprise Admins SID out in ticket #3 (service ticket):

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/0f880bb8-d912-45ec-9cd2-9c2d965fb432/image7.png)

We do not have any other SIDs in our ticket that allow us access to C$ of the parent DC, which is why we get access denied. 

Repeating the test with Method #2 attack is needless as that will produce an inter-realm TGT with Enterprise Admins SID in ExtraSids similar to ticket #1 which was not access given with SID filtering enabled.

# SID filtering vs unconstrained delegation and printer bug

In part 2 Method #3 we compromised the parent domain by capturing a TGT from the parent domain’s DC by abusing unconstrained delegation on the child DC and the printer bug on the parent DC.

Method #3 is reproduced below now with SID filtering enabled for the trust from the parent to the child domain. SpoolSample is run, but Rubeus do not capture any TGT for the parent domain DC:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/4ec920d7-7569-46ac-8888-4e8c658bed19/image8.png)

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/db41201f-f548-4cfd-9bec-1face28bf638/image9.png)

We have also tried to connect manually to the child DC using other services like CIFS, but no TGT would appear in memory. Only non-network login (non-type 3) would generate a TGT. We have tested with Mimikatz as well to make sure it was not a Rubeus issue.

Our tests indicated that SID filtering breaks the unconstrained delegation functionality. However, we have not found a logical explanation for this or Microsoft documentation describing this behavior. The closest we have found to support our observation is [this article](https://support.microsoft.com/en-us/topic/updates-to-tgt-delegation-across-incoming-trusts-in-windows-server-1a6632ac-1599-0a7c-550a-a754796c291e), which states that unconstrained delegation cannot work over forest and external trust if SID filtering is enabled.

# SID filtering and universal groups

Microsoft has a section on [how SID filtering impacts operations](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755321(v=ws.10)?redirectedfrom=MSDN#how-sid-filtering-impacts-operations), one of the issues being universal groups. As explained in part 1, universal group SIDs of other domains are added to ExtraSids in the user’s PAC, so when SID filtering is enabled, these SIDs will be filtered out. If SID filtering is enabled for the trust from a parent to a child domain, users of a child domain will not be able to access parent domain services with the SIDs of universal groups of the parent domain. However, if universal groups of the child domain have been granted rights in the parent domain, child domain users who are members of these groups will be able to access the parent domain resources.

# SIDs not filtered

We have shown that SID filtering prevents the attacks from part 2, why it seems SID filtering actually could be used as a security boundary between domains. But, Microsoft documentation on SID filtering states that the ["Enterprise Domain Controllers" (S-1-5-9) SID and those described by the trusted domain object (TDO)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280) are allowed through the filter. Additionally, seven SIDs in the SID filtering documentation are marked as _NeverFilter_:

> |SID pattern|Description of the pattern|
> |---|---|
> |S-1-4|NonUnique Authority|
> |S-1-5-15|"This Org"|
> |S-1-5-21-0-0-0-496|Compounded Authentication|
> |S-1-5-21-0-0-0-497|Claims Valid|
> |S-1-5-1000-*|Other Organization|
> |S-1-5-R-*R>1000|Extensible|
> |S-1-10|Passport Authority|

 The TDO is an object representing created in a domain representing a trusted domain. Our root domain has a TDO for the child domain, which holds the child domain name and SID in the securityIdentifier attribute:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/123361a3-6a26-4f9c-a13f-529183956b0b/image10.png)

When the root KDC receives an inter-realm TGT from the child domain, and SID filtering is enabled, it will not filter out any SIDs that begin the securityIdentifier of the child.root.local trustedDomain object, meaning that child domain users’ memberships of groups from the child domain are accepted.

That the Enterprise Domain Controller SID and the seven NeverFilter SIDs are allowed through the SID filter is interesting. We tested them, and they are indeed included in the service ticket. In the screenshot below, we create a golden ticket with Claims Valid SID and Enterprise Domain Controllers SID in ExtraSids:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/87533226-696c-49ff-8b48-2cf48cafeff1/image11.png)

We then access C$ on the root DC. Afterward, we dump the Kerberos tickets to disk, and decrypt the CIFS service ticket using the ROOT-DC-01$ Kerberos secret key to verify Claims Valid SID and Enterprise Domain Controllers SID have passed through the SID filter:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/c3efa029-9049-4ee7-8ed9-4ea3b150d2b3/image12.png)

This means SID filtering as a security boundary can be bypassed if Enterprise Domain Controllers SID or any of the seven NeverFilter SIDs have privileges in the root domain that make it possible to compromise the root domain.

# Part 3 conclusion

We have demonstrated that the three known attack methods from part 2 can be prevented by SID filtering. But we have also seen that there exist SIDs which are allowed through the SID filter. In Part 4 _-_ [Bypass SID filtering research](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research), we explore SID filtering exception SIDs and what permissions are granted to exception SIDs that could allow for new trust attacks.