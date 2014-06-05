(ns ring.middleware.secure-headers
  (:use ring.util.response))

(def SECURE_HEADERS
  {:hsts "Strict-Transport-Security"
   :frame-option-header "X-Frame-Options"
   :content-type-header "X-Content-Type-Options"
   :x-xss-protection-header "X-XSS-Protection"})

(defn- create-hsts-header
  [& [max-age include-subdomains]]
  (str
   "max-age="
   (or max-age "31536000") ";"
   (if include-subdomains "includeSubDomains")))

(defn- create-x-frame-options-header
  [opt]
  (if (map? opt) (str "ALLOW-FROM:" (opt :allow-from)) opt))

(defn- create-x-xss-protection-header
  [& [value mode]]
  (str
   value (if mode (str "; mode=" mode) "")))

(defn wrap-hsts-header
  "Add the 'Strict-Transport-Security' header
   response."
  [handler & [options]]
  (let [opts (or options {:max-age 31536000 :include-subdomains false})]
   (fn [req]
    (if-let [resp (handler req)]
      (if (get-in resp [:headers (:hsts SECURE_HEADERS)])
        resp
        (header resp (:hsts SECURE_HEADERS)
                (create-hsts-header (opts :max-age) (opts :include-subdomains))))))))

(defn wrap-x-frame-options-header
  ""
  [handler & [options]]
  (let [option (or options "SAMEORIGIN")]
    (fn [req]
      (if-let [resp (handler req)]
        (if (get-in resp [:headers (:frame-option-header SECURE_HEADERS)])
          resp
          (header resp (:frame-option-header SECURE_HEADERS) (create-x-frame-options-header option)))))))

(defn wrap-x-content-type-options-header
  ""
  [handler]
  (let [option "nosniff"]
    (fn [req]
      (if-let [resp (handler req)]
        (if (get-in resp [:headers (:content-type-header SECURE_HEADERS)])
          resp
          (header resp (:content-type-header SECURE_HEADERS) option))))))

(defn wrap-x-xss-protection-header
  ""
  [handler & [options]]
  (let [option (or options {:value 1 :mode "block"})]
    (fn [req]
      (if-let [resp (handler req)]
        (if (get-in resp [:headers (:x-xss-protection-header SECURE_HEADERS)])
          resp
          (header resp (:x-xss-protection-header SECURE_HEADERS)
                  (create-x-xss-protection-header (option :value) (option :mode))))))))

(defn wrap-secure-headers
  "Composition of different security headers chained together"
  [handler & [options]]
  (-> handler
      (wrap-hsts-header (:hsts options))
      (wrap-x-frame-options-header (:frame-option options))
      (wrap-x-content-type-options-header)
      (wrap-x-xss-protection-header (:xss options))))
