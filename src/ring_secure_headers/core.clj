(ns ring-secure-headers.core
  (:use ring.util.response
        ring-secure-headers.hsts))

(defn wrap-secure-headers
  "Composition of different security headers chained together"
  [handler & [options]]
  (-> handler
   (wrap-hsts-header)))