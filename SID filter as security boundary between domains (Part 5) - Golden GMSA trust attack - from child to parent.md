Originally published on https://blog.improsec.com April 6th 2022.
https://blog.improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent
_Authors: Jonas Bülow Knudsen, Martin Sohn Christensen, Tobias Thorbjørn Munch Torp


This is part five of a seven part series. Check out [part 1 Kerberos authentication explained](https://improsec.com/tech-blog/o83i79jgzk65bbwn1fwib1ela0rl2d) for links to the others.

In [part four of this series](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research), we saw how the replication of Configuration naming context (NC) to child domains allows for the **GPO on site attack**. Right after discovering this, the [GoldenGMSA tool by Yuval Gordon](https://www.semperis.com/blog/golden-gmsa-attack/) was released, which makes it possible to compromise the password of a Group Managed Service Account’s (gMSA) in a domain if high privileges are obtained in the same domain.

Combining the Configuration NC replication attack research and the GoldenGMSA tool we found that another child to parent attack is possible.

# Content

- The GoldenGMSA tool
    
- GoldenGMSA attack – from child to parent
    
- Mitigation and detection
    
- Part 5 conclusion
    

# The GoldenGMSA tool

Here is a demonstration of the original attack:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/99fd17e3-c064-4e96-8575-20b956001c1b/Picture2.png)

Privileges required to compromise a gMSA are either:

- Member of Enterprise Admins
    
- Member of Domain Admins
    
- SYSTEM on a DC
    

By requiring such high privileges this attack therefore seems like a domain persistence technique, to quote Yuval:

“_The Golden GMSA attack occurs when an attacker dumps a KDS root key’s relevant attributes and then uses them to generate the password for associated gMSA accounts offline. The Golden GMSA attack is somewhat similar to the Golden Ticket attack, which allows attackers who compromise the krbtgt account to forge Ticket Granting Tickets (TGTs) as long as the krbtgt password remains unchanged._ 

_One notable difference between a Golden Ticket attack and the Golden GMSA attack is that we are not aware of a way of rotating the KDS root key secret. Therefore,_ **_if a KDS root key is compromised, there is no way to protect the gMSAs associated with it_**_. The only mitigation in such a scenario is to create new gMSAs with a new KDS root key._ “

# GoldenGMSA attack – from child to parent

We found that the GoldenGMSA attack also makes it possible to obtain gMSA passwords across intra-forest trusts, so that a child domain can compromise gMSA’s of a parent domain.

As specified by Yuval, the attack requires access to the following attributes of the KDS Root Key in the forest root:

- cn
    
- msKds-SecretAgreementParam
    
- msKds-RootKeyData
    
- msKds-KDFParam
    
- msKds-KDFAlgorithmID
    
- msKds-CreateTime
    
- msKds-UseStartTime
    
- msKds-Version
    
- msKds-DomainID
    
- msKds-PrivateKeyLength
    
- msKds-PublicKeyLength
    
- msKds-SecretAgreementAlgorithmID
    

The GoldenGMSA tool obtains these using LDAP by reading attributes of msKds-ProvRootKey objects in “CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,DC=root,DC=local”:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/0690893f-586d-4365-bc81-385ec1250f5b/Picture3.png)

Looking at the DACL we find ‘root\Domain Admins’, ‘root\Enterprise Admins’, and SYSTEM are granted ‘Full control’:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/3344afde-eaf6-47ba-ba88-5ed0c5d41352/Picture5.png)

Reading the source code of the GoldenGMSA tool we found out that the two arguments:

- ‘gmsainfo’ queries the **current domain** (child domain) for gMSA accounts, where none exist (we want to compromise the parent domain)
    
- ‘kdsinfo’ queries the **forest root** (parent domain) for the KDS key attributes, which is not allowed by the ACL
    

The tool does therefore not work in a child domain:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/37f38049-2914-492a-9af7-f5e53a009d9b/Picture7.png)

But as described in part 4 in the **GPO on site attack**, the Configuration NC is replicated to child DCs, and we can therefore read KDS Root Keys in the DCs local replica with SYSTEM privileges:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/20260d9f-f63c-4a45-a95c-eb7b358a680c/Picture8.png)

This resulted in the discovery of another trust attack, [which we added as a pull request to the GoldenGMSA](https://github.com/Semperis/GoldenGMSA/pull/6) with the parameters ‘-d, --domain’ and ‘-f, --forest’:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/b68ad4cd-471f-4198-a606-4a0fa8afc9a7/Picture9.png)

To demonstrate the Golden gMSA trust attack, we ran the following from ‘child.root.local’.

1. The parent domain (root.local) is queried for gMSA accounts
    
2. The child domain (child.root.local) is queried for the KDS Root Key
    
3. The password of the parent’s gMSA is computed by querying both domains again (known as the ‘online’ attack)
    

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/3b83eaa6-3a65-404e-ba2e-0251d331ae5b/Picture5.png)

The password of the parent’s gMSA is computed again on a non-domain joined system by supplying the KDS key and gMSA info from above (known as the ‘offline’ attack):

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/760a9d5d-d8d4-4579-a07d-cee562ae41aa/Picture7.png)

# Mitigation and detection

We believe no mitigations exist against this attack because the mitigation would be to prevent replication of KDC keys in the Configuration NC which we do not believe is possible.

Detection of the original single-domain Golden gMSA attack is [described in the tool’s original blog post](https://www.semperis.com/blog/golden-gmsa-attack/) and is done by detecting successful read access to the msKds-RootKeyData attribute of any KDS root key objects in the parent domain.

Detection of our demonstrated Golden gMSA trust attack is different since KDS root key objects are not read in the parent domain. We also cannot trust objects which are replicated to the child domain, since we must assume attackers have control of it. Defenders should therefore configure a SACL on gMSAs in the parent domain to alert on successful read access to the ‘msDS-ManagedPasswordId’ attribute on every gMSA / ‘msDS-GroupManagedServiceAccount’ object in the domain, this can be done by adding a SACL to:

- The ‘Managed Service Accounts’ container and inherited to any ‘msDS-GroupManagedServiceAccount’ object
    
- The defaultSecurityDescriptor attribure of the ‘ms-DS-Group-Managed-Service-Account’ schema class, so that any new gMSA object has auditing by default.
    
    - The following SDDL can be appended to the default defaultSecurityDescriptor attribute: S:AI(OU;SA;RP;0e78295a-c6d3-0a40-b491-d62251ffa0a6;;WD)
        

The SACL will be present on any new gMSA:

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/f85a041d-23d0-42b1-ab97-9ddb2650ee8d/Picture11.png)

Once the SACL is configured, any attempt to read the attribute required for an attack will generate the following security events on the parent DC where:

- Event ID: 4662
    
- Subject: is not from the gMSA's own domain
    
- Object type: msDS-GroupManagedServiceAccount
    
- Access: Read Property
    
- Properties: Read Property {0e78295a-c6d3-0a40-b491-d62251ffa0a6} (msDS-ManagedPasswordId)
    

![](https://images.squarespace-cdn.com/content/v1/5bbb4a7301232c6e6c8757fa/cb577d1b-b17e-44b2-803e-7b1dae036b17/Picture12.png)

# Part 5 conclusion

This post demonstrated another intra-forest trust attack - how the replication of the parent domain’s Configuration container allows a child domain to compromise gMSAs of a parent domain using the GoldenGMSA tool.

The compromise of a parent domain’s gMSA may not allow for instant parent domain compromise, but, as you will see in [part 6](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent), the Configuration container replication allows for another powerful child-to-parent attack – a compromise of the parent domain’s schema, just as if we were members of Schema Admins.