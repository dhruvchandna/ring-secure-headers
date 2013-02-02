(ns ring.middleware.secure-headers
  (:use ring.util.response))

(defn- create-hsts-header
  [& [max-age include-subdomains]]
  (str
   "max-age="
   (if max-age max-age "31536000") ";"
   (if include-subdomains "includeSubDomains")))

(defn wrap-hsts-header
  "Add the 'Strict-Transport-Security' header
   response."
  [handler & [options]]
  (let [opts (if options options {:max-age 31536000 :include-subdomains false})]
   (fn [req]
    (if-let [resp (handler req)]
      (if (get-in resp [:headers "Strict-Transport-Security"])
        resp
        (header resp "Strict-Transport-Security"
                (create-hsts-header (opts :max-age) (opts :include-subdomains))))))))



(defn wrap-secure-headers
  "Composition of different security headers chained together"
  [handler & [options]]
  (-> handler
   (wrap-hsts-header (:hsts options))))