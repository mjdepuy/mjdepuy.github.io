# Buzz Buzz Little Bee

This post was a tiny foray back into the world of reverse engineering. And what better sample to get back into things than the newly discovered [Bumblebee](https://malpedia.caad.fkie.fraunhofer.de/details/win.bumblebee)!

The first article (from a well known threat analysis group) was done by *Google's Threat Analysis Group*. The report can be found (here)[https://blog.google/threat-analysis-group/exposing-initial-access-broker-ties-conti/].

The report claims the malware has ties to (Conti)[https://attack.mitre.org/software/S0575/] group, a well known Ransomware-as-a-Service provider active since about 2019. In March, Google had discovered a new malware, titled BUMBLEBEE because of the User-Agent string used. Below is an analysis of a recent sample pulled from (malware-traffic-analysis.net)[https://www.malware-traffic-analysis.net/].

### Initial Infection

Initial access to a victim machine is gained through attaching an ISO to an email or through hosting the ISO file on a website the email may navigate the user to. This method gets around the fact that Microsoft has stated, ("Macros from the internet will be blocked by default in Office")[https://docs.microsoft.com/en-us/deployoffice/security/internet-macros-blocked]. This is great news for everyone! However, this has meant threat actors will devise methods to get around this block, and Conti has found a way.

Inside the ISO file are two files: a LNK file (Windows uses these as shortcut files, handy for quick IOCs) and a DLL file.

```
    Relative Path: ..\..\..\..\Windows\System32\cmd.exe
    Arguments: /c start rundll32.exe mkl2n.dll,kXlNkCKgFC
```

The above is output from (LECmd)[https://ericzimmerman.github.io/#!index.md], one of Eric Zimmerman's great tools! We can see from the relative path and arguments that `cmd.exe` will be executed, further executing `rundll32.exe` with the DLL as an argument. `rundll32.exe` typically has the following format when being called:

```
    rundll32.exe [DLL NAME],[DLL EXPORT FUNCTION NAME | ORDINAL]
```

I will explain what an ordinal is after this analysis. But with the above format, we can see that `rundll32.exe` is launching the DLL file in that ISO attachment, and calling one of its export functions, `kXlNkCKgFC`. 

