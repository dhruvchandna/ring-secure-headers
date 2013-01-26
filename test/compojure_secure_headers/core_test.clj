(ns compojure-secure-headers.core-test
  (:use clojure.test
        compojure-secure-headers.core))

(deftest wrap-hsts-header-test
  (testing "response without hsts header"
    (let [handler (wrap-hsts-header (constantly {}))]
      (is (= (handler {}) {:headers {"Strict-Transport-Security" "max-age=31536000;"}}))))
  
  (testing "response with hsts header already set"
    (let [handler (wrap-hsts-header
                   (constantly {:headers {"Strict-Transport-Security" "max-age=0;"}}))]
      (is (= (handler {}) {:headers {"Strict-Transport-Security" "max-age=0;"}})))))

