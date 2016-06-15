package com.cisco.opendns.investigate

import scala.util.parsing.json._
import scalaj.http._

class openDNSInvestigate(authKey: String,proxyHost: String="",proxyPort: Int=0) extends Serializable {

  private val baseUri     = "https://investigate.api.opendns.com"
  private val authHeader  = "Bearer " + authKey
  private val domainRegex = "[a-zA-Z]+[a-zA-Z0-9-]+\\.[a-z]+{2,}".r
  private val emailRegex  = "[a-zA-Z0-9_.+-]+@[a-zA-Z]+[a-zA-Z0-9-]+\\.[a-z]+{2,}".r
  private val ipRegex     = "([0-9]+\\.){3,}[0-9]+".r


  private val uriMap = Map[String,String](
    "whois" -> "%s/whois/%s.json",
    "categorization" -> "%s/domains/categorization/%s",
    "cooccourances"-> "%s/recommendations/name/%s.json",
    "whoisEmails"-> "%s/whois/emails/%s.json",
    "domainSecurity"-> "%s/security/name/%s.json",
    "related"-> "%s/links/name/%s.json",
    "domainTags"-> "%s/domains/%s/latest_tags",
    "latestDomains"-> "%s/ips/%s/latest_domains",
    "nsWhoIs"-> "%s/whois/nameservers/%s",
    "search"-> "%s/search/$query",
    "ipRRHistory"-> "%s/dnsdb/ip/%s",
    "domainRRHistory"-> "%s/dnsdb/name/$domainName/$queryType.json"
  )

  private def getParse(uri: String): Option[Any] = {
    var request: HttpRequest = Http(uri)
      .method("GET")
      .header("Authorization", authHeader)
      .header("Content-Type", "application/json")
      .header("Charset", "UTF-8")

    if(proxyPort!=0) request = request.proxy(proxyHost,proxyPort)

    JSON.parseFull(request.asString.body)
  }

  private def getParseObj(obj: String,uri: String, objregex: scala.util.matching.Regex): Option[Any] = {
    val validObj = objregex.findFirstIn(obj)
    validObj match {
      case Some(testObj: String) => getParse(uri.format(baseUri,validObj.get))
      case None => None

    }
  }

  private def getParseDomain(d: String, uri: String): Option[Any] = getParseObj(d,uri,domainRegex)
  private def getParseIp(ip: String, uri: String): Option[Any] = getParseObj(ip,uri,ipRegex)
  private def getParseEmail(em: String, uri: String): Option[Any] = getParseObj(em,uri,emailRegex)

  def getDomain(d: String)            = getParseDomain(d,uriMap("whois")).getOrElse(None)
  def domainCategorization(d: String) = getParseDomain(d,uriMap("categorization")).getOrElse(None)
  def cooccourances(d: String)        = getParseDomain(d,uriMap("cooccourances")).getOrElse(None)
  def domainWhoisEmails(em: String)   = getParseEmail(em,uriMap("whoisEmails")).getOrElse(None)
  def domainsecurity(d: String)       = getParseDomain(d,uriMap("domainSecurity")).getOrElse(None)
  def related(d: String)              = getParseDomain(d,uriMap("related")).getOrElse(None)
  def domainTags(d: String)           = getParseDomain(d,uriMap("domainTags")).getOrElse(None)
  def latext_domains(ip: String)      = getParseIp(ip,uriMap("latestDomains")).getOrElse(None)
  def ns_whois(ns: String)            = getParse(baseUri + "/whois/nameservers/" + ns).getOrElse("Not Found")
  def search(query: String)           = getParse(baseUri + "/search/" + query).getOrElse("Not Found")
  def ipRrHistory(ip: String, queryType: String)    = getParseIp(ip,uriMap("ipRRHistory"))
  def domainRrHistory(d: String, queryType: String) =  getParseDomain(d,uriMap("domainRRHistory"))

}
