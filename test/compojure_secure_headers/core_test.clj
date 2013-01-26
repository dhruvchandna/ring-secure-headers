(ns compojure-secure-headers.core-test
  (:use clojure.test
        compojure-secure-headers.core))

(deftest wrap-hsts-header-test
  (testing "response without hsts header"
    (let [handler (wrap-hsts-header (constantly {}))]
      (is (= (handler {}) {:headers {"Strict-Transport-Security" "max-age=31536000;"}})))))

