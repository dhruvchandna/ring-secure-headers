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
      (is (= (handler {}) {:headers {"Strict-Transport-Security" "max-age=0;"}}))))

  (testing "response with custom max-age"
    (let [handler (wrap-hsts-header
                   (constantly {}) {:max-age 1000})]
      (is (= (handler {}) {:headers {"Strict-Transport-Security" "max-age=1000;"}}))))  

  (testing "response with default max-age and custom domain inclusion"
    (let [handler (wrap-hsts-header
                   (constantly {}) {:include-subdomains true})]
      (is (= (handler {})
             {:headers {"Strict-Transport-Security" "max-age=31536000;includeSubDomains"}}))))  

  (testing "response with custom max-age and custom domain inclusion"
    (let [handler (wrap-hsts-header
                   (constantly {}) {:max-age 2000 :include-subdomains true})]
      (is (= (handler {})
             {:headers {"Strict-Transport-Security" "max-age=2000;includeSubDomains"}}))))
  
  (testing "nil response"
    (let [handler (wrap-hsts-header (constantly nil))]
      (is (nil? (handler {}))))))

