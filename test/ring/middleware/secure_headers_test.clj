(ns ring.middleware.secure-headers-test
  (:use clojure.test
        ring.middleware.secure-headers))

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


(deftest wrap-x-frame-options-header-test
  (testing "response with default x-frame-option"
    (let [handler (wrap-x-frame-options-header (constantly {}))]
      (is (= (handler {}) {:headers {"X-Frame-Options" "SAMEORIGIN"}}))))

  (testing "response with x-frame-option already set"
    (let [handler (wrap-x-frame-options-header (constantly {:headers {"X-Frame-Options" "DENY"}}))]
      (is (= (handler {}) {:headers {"X-Frame-Options" "DENY"}}))))
  
  (testing "response with x-frame-option set to DENY"
    (let [handler (wrap-x-frame-options-header (constantly {}) "DENY")]
      (is (= (handler {}) {:headers {"X-Frame-Options" "DENY"}}))))

  (testing "response with x-frame-option set to ALLOW"
    (let [handler (wrap-x-frame-options-header (constantly {}) {:allow-from "example.com"})]
      (is (= (handler {}) {:headers {"X-Frame-Options" "ALLOW-FROM:example.com"}})))))


(deftest wrap-secure-headers-test
  (testing "response with all default security headers"
    (let [handler (wrap-secure-headers (constantly {}))]
      (is (= (handler {}) {:headers {"Strict-Transport-Security" "max-age=31536000;"
                                     "X-Frame-Options" "SAMEORIGIN"}}))))
  
  (testing "response with overiding configuration"
    (let [handler (wrap-secure-headers (constantly {})
                                       {:hsts {:max-age 1000 :include-subdomains true}
                                        :frame-option "DENY"})]
      (is (= (handler {}) {:headers {"Strict-Transport-Security" "max-age=1000;includeSubDomains"
                                     "X-Frame-Options" "DENY" }})))))