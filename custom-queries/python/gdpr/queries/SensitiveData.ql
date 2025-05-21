import python

/**
 * Define sensitive variable names.
 */
predicate isSensitiveName(string id) {
  id = "email" or id = "password" or id = "ssn" or id = "dob"
}

/**
 * Detect print(...) leaks.
 */
predicate isPrinted(Name n, string tag) {
  tag = "printed" and
  exists(Call c |
    c.getLocation().getStartLine() = n.getLocation().getStartLine() and
    c.getLocation().getFile() = n.getLocation().getFile() and
    c.toString().regexpMatch(".*print.*") and
    isSensitiveName(n.getId())
  )
}

/**
 * Detect sensitive data being written to files (e.g. f.write or f.writelines).
 */
predicate isWritten(Name n, string tag) {
  tag = "written" and
  exists(Call c |
    c.getLocation().getStartLine() = n.getLocation().getStartLine() and
    c.getLocation().getFile() = n.getLocation().getFile() and
    c.toString().regexpMatch(".*open.*") and
    isSensitiveName(n.getId())
  )
}


/**
 * Detect sensitive data being inserted into a database (e.g. db.insert).
 */
predicate isInserted(Name n, string tag) {
  tag = "inserted" and
  exists(Call c |
    c.getFunc().(Attribute).getName() = "insert" and
    exists(int i | c.getArg(i) = n) and
    isSensitiveName(n.getId())
  )
}

/**
 * Detect sensitive data being stored in cookies (e.g. response.set_cookie).
 */
predicate isCookie(Name n, string tag) {
  tag = "cookie-responded" and
  exists(Call c |
    c.getFunc().(Attribute).getName() = "set_cookie" and
    exists(int i | c.getArg(i) = n) and
    isSensitiveName(n.getId())
  )
}

/**
 * Detect logging.
 */
predicate isLogged(Name n, string tag) {
  tag = "logged" and
  exists(Call c, Attribute attr |
    attr = c.getFunc() and
    attr.getObject().(Name).getId() in ["logging", "logger"] and
    attr.getName() in ["info", "error", "warning", "debug", "critical"] and
    exists(int i | c.getArg(i) = n) and
    isSensitiveName(n.getId())
  )
}

/**
 * Detect sensitive data passed as part of a dictionary to requests.post(...)
 */
predicate isSentViaHttp(Name n, string tag) {
  tag = "sent-http" and
  exists(Call c |
    c.getLocation().getFile() = n.getLocation().getFile() and
    c.getLocation().getStartLine() = n.getLocation().getStartLine() and
    c.getFunc().(Attribute).getName() = "post" and
    isSensitiveName(n.getId())
  )
}


/**
 * Detect HTTP responses.
 */
predicate isReturnedHttp(Name n, string tag) {
  tag = "returned-http" and
  exists(Call c |
    c.getFunc().(Name).getId() in ["Response", "make_response"] and
    exists(int i | c.getArg(i) = n) and
    isSensitiveName(n.getId())
  )
}

/**
 * Detect if sensitive data is returned via jsonify (e.g. jsonify({"email": email})).
 */
predicate isReturnedInJson(Name n, string tag) {
  tag = "json-returned" and
  exists(Call c |
    (
      // Handle both: jsonify(...) and flask.jsonify(...)
      c.getFunc().(Attribute).getName() = "jsonify" or
      c.getFunc().(Name).getId() = "jsonify"
    ) and
    c.getLocation().getFile() = n.getLocation().getFile() and
    c.getLocation().getStartLine() = n.getLocation().getStartLine() and
    isSensitiveName(n.getId())
  )
}

/**
 * Detect risky sending of sensitive data.
 */
predicate isUsedWithoutConsent(Name n, string tag) {
  tag = "no-consent" and
  isSensitiveName(n.getId()) and
  exists(Call c |
    c.getLocation().getFile() = n.getLocation().getFile() and
    c.getLocation().getStartLine() = n.getLocation().getStartLine() and
    c.toString().regexpMatch(".*(send|notify|send_email).*")
  ) and
  not exists(Name c |
    c.getLocation().getFile() = n.getLocation().getFile() and
    c.getLocation().getStartLine() < n.getLocation().getStartLine() and
    c.toString().regexpMatch(".*consent.*")
  )
}

/**
 * Detect if we are passing a sensitive value by attributing
 * or concatenating it to a URL.
 */
predicate isSensitiveInUrl(Name n, string tag) {
  tag = "url-assigned" and
  isSensitiveName(n.getId()) and
  exists(Name v |
    v.getLocation().getFile() = n.getLocation().getFile() and
    v.getLocation().getStartLine() = n.getLocation().getStartLine() and
    v.toString().regexpMatch("(?i)url|link|http|https")  // URL context
  ) and
  // No hashing, encryption, or processing function nearby
  not exists(Name fn |
    fn.getLocation().getFile() = n.getLocation().getFile() and
    fn.getLocation().getStartLine() = n.getLocation().getStartLine() and
    fn.toString().regexpMatch("(?i)hash|encrypt|encode|digest|hash_email")
  )
}

/**
 * Check if the sensitive name is passed as part of a query
 */
predicate isInSql(Name n, string tag) {
  tag = "in-sql" and
  isSensitiveName(n.getId()) and
  exists(Name v |
    v.getLocation().getFile() = n.getLocation().getFile() and
    v.getLocation().getStartLine() = n.getLocation().getStartLine() and
    v.toString().regexpMatch("(?i)query|sql|sql_query")
  )
}

/**
 * Detect sensitive data included in exception messages.
 */
predicate isInException(Name n, string tag) {
  tag = "in-exception" and
  isSensitiveName(n.getId()) and
  exists(Call c |
    c.getLocation().getFile() = n.getLocation().getFile() and
    c.getLocation().getStartLine() = n.getLocation().getStartLine() and
    c.toString().regexpMatch(".*(Exception|Error).*") and
    n.getLocation().getStartLine() = c.getLocation().getStartLine()
  )
}

/**
 * Detect sensitive variables being attributed to local/session storage.
 */
predicate isStoredLocally1(Name n, string tag) {
  tag = "stored-locally" and
  isSensitiveName(n.getId()) and
  exists(Name v |
    v.getLocation().getFile() = n.getLocation().getFile() and
    v.getLocation().getStartLine() = n.getLocation().getStartLine() and
    v.toString().regexpMatch("(?i)sessionStorage/*|localStorage/*")
  )
}

/**
 * Detect sensitive variables being attributed to local/session storage.
 */
predicate isStoredLocally2(Name n, string tag) {
  tag = "stored-locally" and
  exists(Call c |
    c.getLocation().getStartLine() = n.getLocation().getStartLine() and
    c.getLocation().getFile() = n.getLocation().getFile() and
    c.toString().regexpMatch(".*localStorage|sessionStorage.*") and
    isSensitiveName(n.getId())
  )
}

/**
 * Detect if sensitive data is returned via an HTTP redirect (e.g. return redirect()).
 */
predicate isReturnedInRedirect(Name n, string tag) {
  tag = "redirect-returned" and
  isSensitiveName(n.getId()) and
  exists(Call c |
    c.getLocation().getFile() = n.getLocation().getFile() and
    c.getLocation().getStartLine() = n.getLocation().getStartLine() and
    c.toString().regexpMatch(".*redirect.*")
  )
}

/**
 * Aggregating all predicates (to be used for dispatcher)
 */
predicate sensitiveLeak(Name n, string tag) {
  isPrinted(n, tag) or
  isWritten(n, tag) or
  isInserted(n, tag) or
  isCookie(n, tag) or
  isLogged(n, tag) or
  isSentViaHttp(n, tag) or
  isReturnedHttp(n, tag) or
  isReturnedInJson(n, tag) or
  isUsedWithoutConsent(n, tag) or
  isSensitiveInUrl(n, tag) or
  isInSql(n, tag) or
  isInException(n, tag) or
  isStoredLocally1(n, tag) or
  isStoredLocally2(n, tag) or
  isReturnedInRedirect(n, tag)
}

//Dispatch
from Name n, string filename, int line, string tag
where sensitiveLeak(n, tag)
  and filename = n.getLocation().getFile().getRelativePath()
  and line = n.getLocation().getStartLine()
select n, "Sensitive variable '" + n.getId() + "' " + tag + " in file: " + filename + " on line " + line.toString()
