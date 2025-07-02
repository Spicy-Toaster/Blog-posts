
Originally published on https://medium.com/ february 27th 2025. [https://blog.improsec.com/tech-blog/the-fundamentals-of-ad-tiering](https://medium.com/@research.tto/lets-get-hard-operating-system-hardening-3708ed85fb8f) Authors: Tobias Torp.

# Why Harden?

Hardening is a catch all term for making security better and systems harder to penetrate. Often it involves the practice of disabling and/or removing unnecessary features from operating systems which is called OS hardening.

When we remove old, unused or unneeded features such as autoplay, allowing normal users to enroll 10 machines to the domain, or SMBv1, we improve the security of a system by removing possible points of attack and by forcing the system to use newer and more secure features and protocols.

A surprisingly large number of features and protocols can be removed from Windows operating systems due to the fact that Microsoft designs for backwards compatibility, and that Windows is overfilled with features. I have yet to hear of an organization that makes use of all features that are built into Windows, though plenty make use of old and insecure protocols.

## **Backwards Compatibility**

So why don’t businesses just update their software? Well, Microsoft designs their systems for backwards compatibility to be able to work with legacy systems. In fact, Windows Server 2025 was just released with a shiny new forest level, and it still has the group “Pre-Windows 2000 Compatible Access”. The entire purpose of that group is for a modern updated domain to be able to work with legacy systems that are designed to work with Windows permissions from before the year 2000.

They do this because a lot of organizations have been up and running for a long time, and they have invested in software 20 years ago (or 5 years ago and the software is just bad) which is designed to be run on old operating systems. The businesses are then sometimes built up around this legacy software and so they cannot get rid of it without spending a lot of time and work (ie. money). And it works, so why change it…?

## **Unnecessary features**

But just because Microsoft likes to accommodate us, does not mean we should allow every feature to be turned on.

Even with legacy systems, a lot can still be turned off which have the potential to limit what an attacker can do. It is not likely to stop an attack all by itself, but that is why we have defence in depth.

What it can do though is force an attacker to spend time bypassing our security measures and potentially be a lot more noisy. And that is a win for the defenders. It gives us both more time and opportunities to discover and isolate an attacker.

It is important to keep in mind though, that this is not a

not a silver bullet. It will not solve all your security problems, but it will definitely raise your security maturity and give you a nice baseline.

![](https://miro.medium.com/v2/resize:fit:604/0*G-HGybfRApsCiIxy)

## Please remember

Setting up a hardening baseline for all devices takes time and isn’t something you should jump into right away if you’re dealing with an environment that’s never had any security work done. It’s better to tackle the basics first.

In the event that you haven’t done any security on the network, I can assure you that there are other more obvious and more critical attack paths to close before you start the lengthy process of OS hardening. It does not matter that you turn off SMBv1 or set stricter User Access Controls if it is possible to just run eternal blue on your 2003 domain controller or just dump lsass and get domain admin credentials. Quick side tip: If you want to find those vulnerabilities, PingCastle and PurpleKnight are both excellent tools for finding security concerns in an Active Directory.

A benefit to point out to management about OS hardening is that it is, in a sense, cheap. No expensive tools or consultants are necessary, mostly it just takes time. Time to read and design your hardening level and time to test. Time which is already factored in as employees’ salary. It is always easier to get approval for meetings instead of some expensive, sometimes nice, tool. Which usually also requires a lot of time to configure.

# Choosing a framework

Servers first. My experience is mostly with Windows servers, so that is the examples I will use here, but the same principles also apply to Linux.

The first and most important step is choosing a framework to follow when implementing OS hardening. Luckily, there is no need to spend a lot of time reinventing the wheel when there are plenty of good wheels to choose from already. There are long lists of security recommendations for all well used operating systems, made by very clever and experienced security experts. STIG, CIS and Microsoft are three well known examples that all have made quality frameworks. Here I will briefly give my opinion on all three of them.

## **STIG**

STIG (Security Technical Implementation Guides)  [https://www.stigviewer.com/stigs](https://www.stigviewer.com/stigs)  [https://cyber.trackr.live/stig](https://cyber.trackr.live/stig)

is a set of guidelines and best practices created by the U.S. Department of Defence. There are almost 900 STIG guides for different systems and different versions of the systems. So, whatever you want to secure, you can likely find a STIG guide for it.

STIGs list the severity of each setting, where to find them and how to fix them.

The fact that STIG list severity of each setting means that if you do not want to go the route of implementing everything, then it is easy to only mitigate those settings that are high severity.

If, for example, you think the setting “_Windows Server 2022 title for legal banner dialog box must be configured with the appropriate text._” is not necessary for your organization, or you do not want to spend time on it because it does not improve security in a technical way, then you can easily skip that, because it is listed near the end of the list under the low severity settings.

The list enables you to sort out all the settings that are kinda nice, but not necessary, to have, and focus only on what can have a big impact for your security.

And keeping your security policies more lean will also give an easier overview as there are less settings to keep track of and for the same reason easier to troubleshoot.

## **CIS**

CIS (Center for Internet Security)  [https://www.cisecurity.org/cis-benchmarks](https://www.cisecurity.org/cis-benchmarks)  is a nonprofit organization that works to better cybersecurity. They have created more than 100 guides that cover more than 25 different vendors. While not as many as STIG, that is still a lot!

CIS benchmarks are very long and detailed. For a simple system, such as MSSQL the benchmark is less than 200 pages. For a Windows Server the benchmark is about 1200 pages.

For each setting they have a description of the setting, a rationale description, an impact description, a default setting note and how to implement the change. This is all very good to know, because it helps us make informed choices about whether we actually want to implement this specific setting or whether we can. Furthermore, it helps us avoid breaking too many things, which both our colleagues and bosses like. It is however important to remember that we cannot avoid breaking anything, the only way to do that is by not doing anything :)

The downside of these many delicious details is that the document is long. Yes, it helps us make informed choices, but it also takes a long time to go through.

## **Microsoft**

A third option is Microsoft’s security baselines.  [https://www.microsoft.com/en-us/download/details.aspx?id=55319](https://www.microsoft.com/en-us/download/details.aspx?id=55319)

They make for a quick and easy option because they are very light on documentation. Microsoft provides less insight than CIS and STIG, but they do come as premade GPOs that are ready for import into your domain. That means they are fast to implement.

They define many of the same settings as CIS and STIG, after all good security is good security. But because they are fast, that also means that if you just import the GPOs and start to apply them, hopefully to a test server first, then you don’t really know what settings you are changing. And this means when something breaks, and something most likely will break, then it is more difficult to troubleshoot because you don’t really know what changes you are making.

If you need to up security fast it is great though, and Microsoft releases new versions every once in a while, so unless you customize them, then you can simply just download and import the updated versions when they are released.

![](https://miro.medium.com/v2/resize:fit:500/0*iUiYgFWSBNMhfcIh)

Personally, I prefer CIS as I believe it is important to know what you are implementing in your domain, and reading through all their documentation (which can be quite interesting) gives you the opportunity to know what settings would not be good for your domain and should be avoided.

If you want the more trimmed down version but still documented version, then using a mix of STIG and CIS is good.

Choose what to implement based on STIG’s severity rating and look the setting up in CIS to know the details of each setting.

# Before you begin

Keep in mind, IT changes fast, and frameworks are not updated everyday. There are always more you can do, and not everything is documented in a framework. Moreover, remember to document your own OS hardening.

Your organization might want to get some kind of certification or get audited at some point. If you can say you comply with this and this framework and have all the documentation ready, then that is very nice.

When documenting a framework like this, I find it easiest to write down the exact version of a framework I am using and then documenting all the settings I am not choosing to include and the reasons for not including them.

I find this far easier than writing all the things I do implement, especially when I have a PDF where that is already listed. This gives a better overview of where I deviate from a framework and why, rather than copying 1000 pages from a PDF to a wiki .

Furthermore, it is important to carefully review the framework you choose before implementing it. If you use a pre-made framework without reviewing them thoroughly you run a higher risk of breaking something in your network because you essentially do not know what you are applying.

Whereas if you carefully review a framework, you know what you are applying. This helps you avoid errors such as disabling printer settings on a printer server or turning off protocols which your 2003 server does not work without.

# Applying a framework

It should go without saying that if you have a test or development environment you should always test there before applying the changes in your production environment. This allows you to be sure that your framework policies will not break something when it is applied in production. It also makes your test/dev environment that much more secure. Which is important considering how often test/dev environments are compromised and used by attackers to pivot to the production environment.

Furthermore, when you start applying your policies it is a good idea to do it in batches, so as to limit the risk of how much might break at once. If you apply your changes everywhere all at once, well then there is a risk that you will break everything everywhere all at once. Probably a very small risk, but an unnecessary one.

The same goes for your workstations. With those it is easier to test on a small group first and then get a few employees from each of the departments to test on. That way you can keep disruptions to a minimum, while making sure that the one department that uses some weird software does not stop working if you roll it to the entire department at once.

Do also remember to talk to your colleagues when implementing OS hardening. If you are the security guy, talk to your sysadmins. If you are the sysadmin, talk to your security guys.

No matter what, tell your support what you are doing, so if they get a lot of tickets or calls because things stop working, they know why. And if you think something might break, talk to the team that uses the application or service you suspect might break. If they have something critical coming up that is on a deadline, they will be very happy to know what is going on and to have the opportunity to ask you to wait for a week.

It costs nothing to be polite and respectful and it makes work a lot more enjoyable when you don’t annoy or piss off your colleagues. Unless you are into that :)

# GPO implementation

As mentioned earlier, it is possible to find premade GPOs. Microsoft’s security baseline is an example, but you can also find exported GPOs on github or various other places on the internet if you feel like going the easy (risky) route. As with all things found on github and the internet though, you really should read and understand what it does before implementing it.

Not reading about or understanding what each setting does carries a certain risk, and another problem with GPOs found on github is that they may not be up-to- date, or made for a different environment with other needs than yours. Or they might be made by someone who is experimenting or just messing around.

Reading the documentation is really the best way to go, even though it does take longer.

Now once you have made your GPOs and want to apply them, it is best to take a backup of your settings first. In case something breaks it is good to have a backup either to roll back to or to use for troubleshooting. If you have a fancy EDR tool, it might be able to give you a baseline analysis and export the current settings.

If you do not have that then a good tool for taking a backup is HardeningKitty ([https://github.com/scipag/HardeningKitty](https://github.com/scipag/HardeningKitty)).

HardeningKitty is a great tool that can both rate how secure a configuration you have, take a backup of current settings and be used to implement hardening. A policy is better for enforcement than a script though. A script has to run as a batch job, whereas a policy gets implemented automatically and the settings configured with it are a lot harder to change as they get locked down due to central control.

I you have read through the documentation and found what does and what does not work for your domain then you can use this site  [https://phi.cryptonit.fr/policies_hardening_interface/interface/windows/](https://phi.cryptonit.fr/policies_hardening_interface/interface/windows/)  to generate a list of settings exported in a .csv that you want HardeningKitty to look for.

That way you only get results for the settings you are interested in rather than the full list. Makes for a far better overview than pulling all the settings, including those that you are not interested in.

CIS also have a tool for auditing, and there is a free version of it too which can be downloaded from here  [https://learn.cisecurity.org/cis-cat-lite](https://learn.cisecurity.org/cis-cat-lite)

They also have a paid version if the budget is not an issue. What tool you choose to use does not matter, what is important is to get the backup.

![](https://miro.medium.com/v2/resize:fit:500/0*_QfI1lyXDCYmxm4n)

When you have created your GPOs it is also a good idea to check if you have already defined the same settings before in other GPOs where they might have different values.

We want to avoid GPO conflicts as it can create issues with what settings end up being applied as some GPOs might be closer to the objects, and as we all know, the GPO closest to the object is the one that wins.

Except if another GPO is enforced. Or if inheritance is disabled somewhere.

And if you have 200 GPOs, or 2000 GPOs, well then, your GPO structure might be messy and difficult to have an overview of, and that is why we want to check for conflicts so we can avoid trying to solve the puzzle of why something we know we turned off is not turned off.

Checking for conflicts is easiest with Policy Analyzer. It is a Microsoft tool that allows you to compare the settings of exported GPOs and show you if the same settings are defined and whether they have different values.

It is very easy to use, just take a backup of your GPOs, load them into Policy Analyzer and let it do the work for you. If you do find settings that have been defined in more than one GPO, you need to make a decision of what GPO to keep that setting in, and if it deviates from the recommendation, then you need to find out the reason it has been defined like that. There might be a good reason for it, and changing it to follow the security recommendation might break something.

You can read about Policy Analyzer here  [https://techcommunity.microsoft.com/blog/microsoft-security-baselines/new-tool-policy-analyzer/701049](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/new-tool-policy-analyzer/701049)

When applying the GPOs there is also a thing called GPO tattooing to consider. GPO tattooing is what is called when settings that are applied with a GPO do not revert back to their previous value when the GPO is no longer applied. It is also called persistent settings.

It becomes an issue if your GPO breaks something and you want to revert back to your previous settings. The only way to revert back is to push a GPO with the opposite settings. If the settings have more than two possible values, it is not so easy as just changing it to the opposite.

This again emphasizes why a backup is important. When you know how your device was configured when it worked, you know how to fix it when you make a mess.

As a general guideline “Administrative Templates” settings are not tattooed while security settings are tattooed. Microsoft also mentions it here  [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/security-policy-settings](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/security-policy-settings).

If you are interested in learning more, there are lots of blog posts written about the subject GPO tattooing, just a google search away.

# Intune policies implementation

Intune has a feature called “Security baselines”. It is multiple Microsoft created and maintained security baselines ready to deploy.

![](https://miro.medium.com/v2/resize:fit:700/0*Fs6bTr-DsLW6JEQv)

In my opinion the default security baselines have the same issue as the premade GPOs. You don’t have a clear overview of what settings are applied, and you do not have an understanding of what the policies do.

However Intune Security Baselines also have the added benefit, or issue, of being maintained by Microsoft. That means that Microsoft keeps them updated and you don’t have to do that manually, but it also means that if Microsoft pushes a bad update out it leaves you in a bad place.

For example, it was reported that in the first half of 2024 an update forgot to include foreign languages, leading to temporarily blocked logins on a lot of workstations.

If you wish to use the security baselines you can find guidance for it here  [https://learn.microsoft.com/en-us/mem/intune/protect/security-baselines](https://learn.microsoft.com/en-us/mem/intune/protect/security-baselines)

As previously stated, I find it better to use a framework with documentation.

If you have already implemented OS hardening but moves a bit more to the cloud and starts to use intune instead of GPOs you can import your GPOs you have already configured to Intune to use as baselines. A guide for that can be found here  [https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/stiging-made-easy---microsoft-endpoint-manager/2422255](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/stiging-made-easy---microsoft-endpoint-manager/2422255)  
The blog is based on STIG but it also goes into how to import your own custom GPOs.

You can also make a device configuration policy to apply your hardening. It will have the same effect as a security baseline. If you have both types of policy and they define the same setting(s) then there is a conflict. It will show the conflict and what setting(s) that is creating the conflict in the policy report. If there is a conflict it will be the most restrictive setting that ends up being applied. For better overview it is better to resolve conflicts.

One reason to use configuration policies could be to keep all your OS policies together, as configuration policies are also used for normal administration of workstations.

As with GPOs, tattooing is also an issue for intune policies. And it is really not clear what settings get tattooed and which does not. Microsoft writes the following

![](https://miro.medium.com/v2/resize:fit:700/0*y_HGlUajCbE2ym9D)

[https://learn.microsoft.com/en-us/mem/intune/configuration/device-profile-troubleshoot#a-profile-is-deleted-or-no-longer-applicable](https://learn.microsoft.com/en-us/mem/intune/configuration/device-profile-troubleshoot#a-profile-is-deleted-or-no-longer-applicable)

Which does not really help us. There is also this very nice blogpost on Intune tattooing and it basically ends with, we don’t know what settings are tattooed and which are not  [https://www.anoopcnair.com/intune-policy-tattooed-not-tattooed-windows-csp/](https://www.anoopcnair.com/intune-policy-tattooed-not-tattooed-windows-csp/)

![](https://miro.medium.com/v2/resize:fit:500/0*iVbCRIz4R8SnSiQj)

So before rolling changes on workstations, again make sure to have a backup of the settings. Workstations are usually configured the same way though, so a backup from each workstation will in most cases be unnecessary. Know how the general config is and make sure to have a backup of the outliers that usually exist, the ones running special software or that is given to employees where the rules are different.

# Wrap up

You can get a lot of security out of hardening. It can really limit what an attacker can do on a server or workstation, and how likely they are to be able to move laterally. It might not stop them completely, but if they are forced to spend time and be noisy, it is a win for the defenders.

And remember to follow a framework. Pick one and stick to it. Remember to update your security policies when the framework gets an update.

And document what you are doing, and what settings do or do not get applied. This will make your life so much easier if you get audited. No one wants to write documentation for what you did two years ago, you can’t remember what you did, and it can feel like doing the same work all over again.

And most importantly

-   Know what you are changing
-   Take a backup
-   Apply carefully.

That is basically the only things needed to minimize disruptions to operations. You cannot avoid something breaking, but you can limit the impact and know what you changed and so fix it faster.

And finally, while it is good to celebrate your hard work, and hopefully watch your next pentester struggle a bit, do not lean back and kick your feet up when done with this. There is always more to do when it comes to security.
