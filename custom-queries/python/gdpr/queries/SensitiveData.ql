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
  isReturnedInJson(n, tag)
}

//Dispatch
from Name n, string filename, int line, string tag
where sensitiveLeak(n, tag)
  and filename = n.getLocation().getFile().getRelativePath()
  and line = n.getLocation().getStartLine()
select n, "Sensitive variable '" + n.getId() + "' " + tag + " in file: " + filename + " on line " + line.toString()
