package com.cisco.opendns.investigate

import org.scalatest.{FunSpec, Matchers}
import scala.util.{Failure, Success, Try}

class openDNSInvestigateSpec extends FunSpec with Matchers {

  val goodDomainName = "cisco.com"
  val badDomainName  = "--asdf3.3s8"
  val goodEmail      = "name@email.com"
  val badEmail       = "name@sdfajla"
  val goodIP         = "123.123.12.13"
  val badIP          = "321.123.12"

  val inv = new openDNSInvestigate(sys.env("apiKey"))

  describe("getDomain") {
    it("returns correct attributes when queried by domain.") {
      val cisco = Try(inv.getDomain(goodDomainName))
      print(cisco)
      cisco match {
        case Success(Success(Some(ret: Map[String,Any])))=>
          ret("domainName") should be ("cisco.com")
          ret("registrantPostalCode") should be ("95134")

      }

      val tco = Try(inv.getDomain("t.co"))
      tco match {
        case Success(Success(Some(ret: Map[String,Any]))) =>
          ret("domainName") should be ("t.co")

      }

    }


    it("fails when an IP is entered instead of a domain name") {
      val IP_err = Try(inv.getDomain(goodIP))

      IP_err match {
        case Success(ret: Map[String,Any])=>
          ret.keySet should contain ("errorMessage")

      }

    }
    it("fails when invalid domain name is input.") {
//      an [com.cisco.opendns.investigate.DomainNameFormatException] should be thrownBy(inv.getDomain(badDomainName))
      val IP_err = Try(inv.getDomain(badDomainName))

      IP_err match {
        case Success(ret: Map[String,Any])=>
          ret.keySet should contain ("errorMessage")

      }

    }
  }

  describe("domainCategorization") {

    it("returns correct category IDs when queried by domain.") {
      val cisco = Try(inv.domainCategorization(goodDomainName))

      cisco match {
        case Success(Success(Some(category: Map[String,Map[String,List[String]]]))) =>
          val cc = category("cisco.com")
          cc("content_categories") should contain ("25")
          cc("content_categories") should contain ("32")
      }
    }

    it("returns correct category IDs when queried by a list of domains.") {
      val cisco = Try(inv.domainCategorization(List("altavista.com","yahoo.com","google.com","cisco.com")))
    }

    it("fails when invalid domain name is input.") {
   //   an [com.cisco.opendns.investigate.DomainNameFormatException] should be thrownBy(inv.getDomain(badDomainName))
      val IP_err = Try(inv.domainCategorization(badDomainName))

      IP_err match {
        case Success(ret: Map[String,Any])=>
          ret.keySet should contain ("errorMessage")

      }
    }
  }

  describe("domainCooccourances") {

    it("returns more than zero cooccourances when queried by domain.") {
      val cisco = Try(inv.cooccourances(goodDomainName))
      cisco match {
        case Success(Success(Some(cooccourances: Map[String,List[List[String]]]))) =>
          cooccourances("pfs2").length should be > 0
      }
    }


    it("fails when invalid domain name is input.") {
      //an [com.cisco.opendns.investigate.DomainNameFormatException] should be thrownBy(inv.getDomain(badDomainName))
      val IP_err = Try(inv.cooccourances(badDomainName))

      IP_err match {
        case Success(ret: Map[String,Any])=>
          ret.keySet should contain ("errorMessage")

      }
    }
  }

  describe("domainWhoisEmails") {
    it("returns correct domains when queried by email address.") {
      val testWhois = Try(inv.domainWhoisEmails("infosec@cisco.com"))
      testWhois match {
        case Success(Success(Some(outMap: Map[String,Map[Any,Any]]))) =>
          outMap("infosec@cisco.com").keySet.size should be > 1
      }
    }

    it("fails when invalid email address is input.") {
     // an [com.cisco.opendns.investigate.EmailAddressFormatException] should be thrownBy(inv.domainWhoisEmails(badEmail))
      val IP_err = Try(inv.domainWhoisEmails(badEmail))

      IP_err match {
        case Success(ret: Map[String,Any])=>
          ret.keySet should contain ("errorMessage")

      }
    }
  }

  describe("domainSecurity") {
    it("returns correct security categories when queried by domain.") {
      val testDomSec = Try(inv.domainsecurity(goodDomainName))
      testDomSec match {
        case Success(Success(Some(outMap: Map[String,Any]))) =>
          outMap.keySet.size should be > 1

      }

    }

    it("fails when invalid domain name is input.") {
      //an [com.cisco.opendns.investigate.DomainNameFormatException] should be thrownBy(inv.getDomain(badDomainName))
      val IP_err = Try(inv.domainsecurity(badDomainName))

      IP_err match {
        case Success(ret: Map[String,Any])=>
          ret.keySet should contain ("errorMessage")

      }
    }

  }

  describe("related") {
    it("returns related domains when queried by domain.") {
      val related = Try(inv.related(goodDomainName))
      related match {
        case Success(Success(Some(related2: Map[String,Any]))) =>
            related2("tb1").asInstanceOf[List[Any]].size should be > 1
      }
    }

    it("fails when invalid domain name is input.") {
 //     an [com.cisco.opendns.investigate.DomainNameFormatException] should be thrownBy(inv.getDomain(badDomainName))
      val IP_err = Try(inv.related(badDomainName))

      IP_err match {
        case Success(ret: Map[String,Any])=>
          ret.keySet should contain ("errorMessage")

      }
    }

  }

  describe("domainTags") {
    it("returns correct domain tags when queried by domain.") {
      true
      //TODO Finish this.
    }

    it("fails when invalid domain name is input.") {
      //an [com.cisco.opendns.investigate.DomainNameFormatException] should be thrownBy(inv.getDomain(badDomainName))
      val IP_err = Try(inv.domainTags(badDomainName))

      IP_err match {
        case Success(ret: Map[String,Any])=>
          ret.keySet should contain ("errorMessage")

      }
    }

  }
  describe("latestDomains") {
    it("returns latest domains when queried by ip.") {
    true
      //TODO
    }

    it("fails when invalid IP Address is input.") {
      //an [com.cisco.opendns.investigate.IPAddressFormatException] should be thrownBy(inv.latest_domains(badIP))
      val IP_err = Try(inv.latest_domains(badIP))

      IP_err match {
        case Success(ret: Map[String,Any])=>
          ret.keySet should contain ("errorMessage")

      }

    }
  }
  describe("nsWhois") {
    it("returns domains when queried by nameserver.") {
      true
      //TODO
    }
  }
  describe("ipRrHistory") {
    it("returns resource record history when queried by IP address.") {
      true
      //TODO
    }

    it("fails when invalid IPN Address is input.") {
      //an [com.cisco.opendns.investigate.IPAddressFormatException] should be thrownBy(inv.ipRrHistory(badIP,"A"))
      val IP_err = Try(inv.ipRrHistory(badIP,"A"))

      IP_err match {
        case Success(ret: Map[String,Any])=>
          ret.keySet should contain ("errorMessage")

      }
    }

  }
  describe("domainRrHistory") {
    it("returns domain resource record history when queried by domain name and resource record type.") {
      true
      //TODO
    }

    it("fails when invalid domain name is input.") {
      //an [com.cisco.opendns.investigate.DomainNameFormatException] should be thrownBy(inv.domainRrHistory(badDomainName,"A"))
      val IP_err = Try(inv.domainRrHistory(badDomainName,"A"))

      IP_err match {
        case Success(ret: Map[String,Any])=>
          ret.keySet should contain ("errorMessage")

      }
   }

  }

}