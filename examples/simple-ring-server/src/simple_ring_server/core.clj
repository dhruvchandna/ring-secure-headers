(ns simple-ring-server.core
  (:use ring.middleware.secure-headers))

(defn handler [request]
  {:status 200
   :headers {"Content-Type" "text/html"}
   :body "Hello World"})

(def app
    (-> handler wrap-secure-headers))
