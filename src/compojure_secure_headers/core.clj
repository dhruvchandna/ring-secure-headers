(ns compojure-secure-headers.core
  (:use ring.util.response))

(defn wrap-hsts-header
  "Add the 'Strict-Transport-Security' header
   response."
  [handler]
  (fn [req]
    (if-let [resp (handler req)]
      (if (get-in resp [:headers "Strict-Transport-Security"])
        resp
        (header resp "Strict-Transport-Security" "max-age=31536000;")))))
