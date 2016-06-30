**scala-opendns**

Scala class to interoperate with the OpenDNS Investigate REST API

**Installation**

    git clone https://github.com/swigley/scala-investigate
**Build**

    $ cd scala-investigate
    $ sbt package

**Basic Usage:**

    $ export API_KEY=<API Key>

    $ scala -cp openDNSInvestigate.jar

    scala>  import com.cisco.opendns.investigate.openDNSInvestigate
    import com.cisco.opendns.investigate.openDNSInvestigate

    scala> val inv = new openDNSInvestigate(sys.env("API_KEY"))
    inv: com.cisco.opendns.investigate.openDNSInvestigate = com.cisco.opendns.investigate.openDNSInvestigate@20b5f2ac

    scala> inv.domainCategorization("amazon.com")
    res1: Any = Map(amazon.com -> Map(status -> 1.0, security_categories -> List(), content_categories -> List(8)))

    scala> inv.cooccourances("test.com")
    res3: Any = Map(pfs2 -> List(List(tfbekk.comyr.com, 0.27268861240271003), List(wellnesspharmacy.com, 0.27268861240271003), List(www.theglobalipcenter.com, 0.11992314780927947), List(ibiblio.org, 0.1030106433788378), List(testmatchingurl.com, 0.06899713816701367), List(mail.benchmarkapps.com, 0.06683319763492734), List(www.cleanitsupply.com, 0.057703464762643694), List(videomatictv.com, 0.03105288759377139)), found -> true)

    scala> inv.domainTags("bibikun.ru")
    res5: Any = List(Map(period -> Map(begin -> 2013-09-16, end -> Current), category -> Malware, url -> null))
