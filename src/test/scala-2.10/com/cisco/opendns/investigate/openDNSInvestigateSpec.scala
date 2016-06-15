package com.cisco.opendns.investigate

import org.scalatest.{FunSpec, Matchers}

class openDNSInvestigateSpec extends FunSpec with Matchers {

  val goodDomainName = "cisco.com"
  val badDomainName = "--asdf3.3s8"
  val goodEmail = "name@email.com"
  val badEmail = "name@sdfajla"
  val goodIP = "123.123.12.13"
  val badIP = "321.123.12"

  val inv = new openDNSInvestigate(sys.env("apiKey"))

  describe("getDomain") {
    it("returns correct attributes when queried by domain.") {
      val cisco = inv.getDomain(goodDomainName)
      cisco match {
        case domain: Map[String,String] =>
          domain("created") should equal ("1987-05-14")
          domain("registrantEmail") should equal ("infosec@cisco.com")

      }
    }

    it("fails when invalid domain name is input.") {
      val error_domain = inv.getDomain(badDomainName)
      error_domain match {
        case None => error_domain should be (None)
      }
    }
  }


  describe("domainCategorization") {

    it("returns correct category IDs when queried by domain.") {
      val cisco = inv.domainCategorization(goodDomainName)
      cisco match {
        case category: Map[String,Map[String,List[String]]] =>
          val cc = category("cisco.com")("content_categories")
          cc should contain ("25")
          cc should contain ("32")
      }
    }

    it("fails when invalid domain name is input.") {
      val error_domain = inv.domainCategorization(badDomainName)
      error_domain match {
        case None => error_domain should be (None)
      }
    }
  }

  describe("domainCooccourances") {

    it("returns more than zero cooccourances when queried by domain.") {
      val cisco = inv.cooccourances(goodDomainName)
      cisco match {
        case cooccourances: Map[String,List[List[String]]] =>
          cooccourances("pfs2").length should be > 0
      }
    }

    it("fails when invalid domain name is input.") {
      val error_domain = inv.cooccourances(badDomainName)
      error_domain match {
        case None => error_domain should be (None)
      }
    }
  }

  describe("domainWhoisEmails") {
    it("returns correct domains when queried by email address.") {
      val testWhois = inv.domainWhoisEmails("infosec@cisco.com")
      //print(testWhois)
      testWhois match {
        case outMap: Map[String,Map[String,Any]] =>
          //TODO Probably want to test for specific values
          outMap("infosec@cisco.com").keySet.size should be > 1
      }

    }
  }

  describe("domainSecurity") {
    it("returns correct security categories when queried by domain.") {
      val testDomSec = inv.domainsecurity(goodDomainName)
      testDomSec match {
        case outMap: Map[String,Any] =>
          outMap.keySet.size should be > 1
      }

    }

    it("fails when invalid domain name is input.") {
      val error_domain = inv.getDomain(badDomainName)
      error_domain match {
        case None => error_domain should be (None)
      }
    }

  }

  describe("related") {
    it("returns related domains when queried by domain.") {

      true
      //TODO
    }

    it("fails when invalid domain name is input.") {
      val error_domain = inv.getDomain(badDomainName)
      error_domain match {
        case None => error_domain should be (None)
      }
    }

  }
  describe("domainTags") {
    it("returns correct domain tags when queried by domain.") {
      true
      //TODO Finish this.
    }

    it("fails when invalid domain name is input.") {
      val error_domain = inv.domainTags(badDomainName)
      error_domain match {
        case None => error_domain should be (None)
      }
    }

  }
  describe("latestDomains") {
    it("returns latest domains when queried by ip.") {
    true
      //TODO
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

  }
  describe("domainRrHistory") {
    it("returns domain resource record history when queried by domain name and resource record type.") {
      true
      //TODO
    }

  }


}