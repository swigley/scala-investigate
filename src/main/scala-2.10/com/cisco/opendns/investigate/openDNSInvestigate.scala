package com.cisco.opendns.investigate

import scala.util.parsing.json._
import scalaj.http._
import scala.util.{Failure, Success, Try}

case class RequestParseException(message: String) extends Exception(message)
case class DomainNameFormatException(message: String) extends Exception(message)
case class IPAddressFormatException(message: String) extends Exception(message)
case class EmailAddressFormatException(message: String) extends Exception(message)

class openDNSInvestigate(authKey: String,proxyHost: String="",proxyPort: Int=0) extends Serializable {

  private val baseUri     = "https://investigate.api.opendns.com"
  private val authHeader  = "Bearer " + authKey
  private val domainRegex = "[a-zA-Z]*[a-zA-Z0-9-]+\\.[a-z]+{2,}".r
  private val emailRegex  = "[a-zA-Z0-9_.+-]+@[a-zA-Z]+[a-zA-Z0-9-]+\\.[a-z]+{2,}".r
  private val ipRegex     = "([0-9]+\\.){3,}[0-9]+".r

  private def listToJson(strList: List[String]): String = "[\"" + strList.mkString("\",\"") + "\"]"

  private val uriMap = Map[String,String](
    "whois"           -> "%s/whois/%s.json",
    "categorization"  -> "%s/domains/categorization/%s",
    "cooccourances"   -> "%s/recommendations/name/%s.json",
    "whoisEmails"     -> "%s/whois/emails/%s.json",
    "domainSecurity"  -> "%s/security/name/%s.json",
    "related"         -> "%s/links/name/%s.json",
    "domainTags"      -> "%s/domains/%s/latest_tags",
    "latestDomains"   -> "%s/ips/%s/latest_domains",
    "nsWhoIs"         -> "%s/whois/nameservers/%s",
    "search"          -> "%s/search/$query",
    "ipRRHistory"     -> "%s/dnsdb/ip/%s",
    "domainRRHistory" -> "%s/dnsdb/name/$domainName/$queryType.json"
  )
  private def reqParse(uri: String,method: String="GET",data: String=""): Try[Option[Any]] = {
    var request: HttpRequest = Http(uri)
      .method(method)
      .header("Authorization", authHeader)
      .header("Content-Type", "application/json")
      .header("Charset", "UTF-8")
    if(method=="POST") request = request.postData(data)
    if(proxyPort!=0)   request = request.proxy(proxyHost,proxyPort)

    Try(JSON.parseFull(request.asString.body))
  }

  private def getParse(uri: String): Any = {
    reqParse(uri,"GET") recoverWith  {
      case e: Exception =>
        throw RequestParseException("Exception getting or parsing HTTP Response. ")
    }
  }

  private def postParse(uri: String,data: List[String]):  Any = {
    reqParse(uri, "POST", listToJson(data)) recoverWith {
      case e: Exception =>
        throw RequestParseException("Exception getting or parsing HTTP Response. ")
    }
  }

  private def raiseDomainNameFormatException(message: String): Any =
    throw new DomainNameFormatException(message)

  private def raiseEmailAddressFormatException(message: String): Any =
    throw new EmailAddressFormatException(message)

  private def raiseIPAddressFormatException(message: String): Any =
    throw new IPAddressFormatException(message)

  private def getParseObj(obj: String,
                            uri: String,
                            objregex: scala.util.matching.Regex,
                            ex: (String) => Any ,
                            errormsg: String): Any = {
    objregex.findFirstIn(obj) match {
      case Some(testObj: String) => getParse(uri.format(baseUri,testObj))
      case None => ex(errormsg)
    }
  }

  private def getParseDomain(d: String, uri: String): Any =
    Try(getParseObj(d, uri,domainRegex,
      raiseDomainNameFormatException,
      s"Domain Name $d: not properly formatted. ")) match {
        case Success(domvar: Any) => domvar
        case Failure(err) =>
            Map("errorMessage" -> s"getParseDomain Error: $err" )
    }

  private def getParseIp(ip: String, uri: String):  Any =
    Try(getParseObj(ip,uri,ipRegex,
      raiseIPAddressFormatException,
      s"IP Address $ip  is not properly formatted. " )) match {
        case Success(ipvar: Any) => ipvar
        case Failure(err) =>
          Map("errorMessage" -> s"getParseIP Error: $err" )
    }

  private def getParseEmail(em: String, uri: String): Any =
    Try(getParseObj(em,uri,emailRegex,
      raiseEmailAddressFormatException,
      s"Email Address $em  is not properly formatted. " )) match {
        case Success(emailvar: Any) => emailvar
        case Failure(err) =>
          Map("errorMessage" -> s"getParseEmail Error: $err" )
    }

  private def getParseDomains(d: List[String], uri: String):  Any =
    Try(postParse(uri,d)) match {
      case Success(domvar: Any) => domvar
      case Failure(err) =>
        Map("errorMessage" -> s"getParseDomains Error $err")
    }

  def domainCategorization(d: Any) = d match {
    case v: String        => getParseDomain(v, uriMap("categorization"))
    case g: List[String]  => getParseDomains(g,uriMap("categorization").format(baseUri,""))
  }

  def getDomain(d: String)         = getParseDomain(d, uriMap("whois"))
  def cooccourances(d: String)        = getParseDomain(d,uriMap("cooccourances"))
  def domainWhoisEmails(em: String)   = getParseEmail(em,uriMap("whoisEmails"))
  def domainsecurity(d: String)       = getParseDomain(d,uriMap("domainSecurity"))
  def related(d: String)              = getParseDomain(d,uriMap("related"))
  def domainTags(d: String)           = getParseDomain(d,uriMap("domainTags"))
  def latest_domains(ip: String)      = getParseIp(ip,uriMap("latestDomains"))
  def ns_whois(ns: String)            = getParse(baseUri + "/whois/nameservers/" + ns)
  def search(query: String)           = getParse(baseUri + "/search/" + query)
  def ipRrHistory(ip: String, queryType: String)    = getParseIp(ip,uriMap("ipRRHistory"))
  def domainRrHistory(d: String, queryType: String) =  getParseDomain(d,uriMap("domainRRHistory"))

}

