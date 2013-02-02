(ns ring.middleware.secure-headers
  (:use ring.util.response))

(def SECURE_HEADERS
  {:hsts "Strict-Transport-Security"
   :frame-option-header "X-Frame-Options"})

(defn- create-hsts-header
  [& [max-age include-subdomains]]
  (str
   "max-age="
   (if max-age max-age "31536000") ";"
   (if include-subdomains "includeSubDomains")))

(defn- create-x-frame-options-header
  [opt]
  (if (map? opt) (str "ALLOW-FROM:" (opt :allow-from)) opt))

(defn wrap-hsts-header
  "Add the 'Strict-Transport-Security' header
   response."
  [handler & [options]]
  (let [opts (if options options {:max-age 31536000 :include-subdomains false})]
   (fn [req]
    (if-let [resp (handler req)]
      (if (get-in resp [:headers (:hsts SECURE_HEADERS)])
        resp
        (header resp (:hsts SECURE_HEADERS)
                (create-hsts-header (opts :max-age) (opts :include-subdomains))))))))

(defn wrap-x-frame-options-header
  ""
  [handler & [options]]
  (let [option (if options options "SAMEORIGIN")]
    (fn [req]
      (if-let [resp (handler req)]
        (if (get-in resp [:headers (:frame-option-header SECURE_HEADERS)])
          resp
          (header resp (:frame-option-header SECURE_HEADERS) (create-x-frame-options-header option)))))))

(defn wrap-secure-headers
  "Composition of different security headers chained together"
  [handler & [options]]
  (-> handler
      (wrap-hsts-header (:hsts options))
      (wrap-x-frame-options-header (:frame-option options))))