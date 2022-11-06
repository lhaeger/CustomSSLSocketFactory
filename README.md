# CustomSSLSocketFactory
A custom SSL Socket Factory applying truststore changes on the fly

This SSLSocketFactory can be used in two ways
- by calling `getDefault()`, which reads the truststore once and returns the same singleton instance on each call. Changes to the truststore require restarting the calling application.
- by calling `getInstance()`, which reads the truststore and returns a new instance on each call. Changes to the truststore become effective on the next call, not requiring a restart of the calling application.



If you want to suppport this project [buy me a coffee](https://www.buymeacoffee.com/lhaeger)!
