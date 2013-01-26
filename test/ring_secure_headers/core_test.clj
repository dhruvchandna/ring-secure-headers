(ns ring-secure-headers.core-test
  (:use clojure.test
        ring-secure-headers.core))

(deftest wrap-secure-headers-test
  (testing "response with all default security headers"
    (let [handler (wrap-secure-headers (constantly {}))]
      (is (= (handler {}) {:headers {"Strict-Transport-Security" "max-age=31536000;"}})))))