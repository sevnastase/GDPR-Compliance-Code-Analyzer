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
    c.getLocation().getStartLine() = n.getLocation().getStartLine() and
    c.getLocation().getFile() = n.getLocation().getFile() and
    c.toString().regexpMatch(".*insert.*") and
    isSensitiveName(n.getId())
  )
}

/**
 * Detect sensitive data being stored in cookies (e.g. response.set_cookie).
 */
predicate isCookie(Name n, string tag) {
  tag = "cookie-responded" and
  exists(Call c |
    c.getLocation().getStartLine() = n.getLocation().getStartLine() and
    c.getLocation().getFile() = n.getLocation().getFile() and
    c.toString().regexpMatch(".*set_cookie.*") and
    isSensitiveName(n.getId())
  )
}

predicate sensitiveLeak(Name n, string tag) {
  isPrinted(n, tag) or
  isWritten(n, tag) or
  isInserted(n, tag) or
  isCookie(n, tag)
}

//Dispatch
from Name n, string filename, int line, string tag
where sensitiveLeak(n, tag)
  and filename = n.getLocation().getFile().getRelativePath()
  and line = n.getLocation().getStartLine()
select n, "Sensitive variable '" + n.getId() + "' " + tag + " in file: " + filename + " on line " + line.toString()
