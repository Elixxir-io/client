////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                    /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package api

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"gitlab.com/elixxir/crypto/signature/rsa"
	"gitlab.com/elixxir/primitives/ndf"
	"reflect"
	"testing"
)

var ExampleJSON = `{"Timestamp": "2019-06-04T20:48:48-07:00", "gateways": [{"Address": "52.25.135.52", "Tls_certificate": "-----BEGIN CERTIFICATE-----\nMIIDgTCCAmmgAwIBAgIJAKLdZ8UigIAeMA0GCSqGSIb3DQEBBQUAMG8xCzAJBgNV\nBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQx\nGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjEaMBgGA1UEAwwRZ2F0ZXdheSou\nY21peC5yaXAwHhcNMTkwMzA1MTgzNTU0WhcNMjkwMzAyMTgzNTU0WjBvMQswCQYD\nVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJQ2xhcmVtb250\nMRswGQYDVQQKDBJQcml2YXRlZ3JpdHkgQ29ycC4xGjAYBgNVBAMMEWdhdGV3YXkq\nLmNtaXgucmlwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9+AaxwDP\nxHbhLmn4HoZu0oUM48Qufc6T5XEZTrpMrqJAouXk+61Jc0EFH96/sbj7VyvnXPRo\ngIENbk2Y84BkB9SkRMIXya/gh9dOEDSgnvj/yg24l3bdKFqBMKiFg00PYB30fU+A\nbe3OI/le0I+v++RwH2AV0BMq+T6PcAGjCC1Q1ZB0wP9/VqNMWq5lbK9wD46IQiSi\n+SgIQeE7HoiAZXrGO0Y7l9P3+VRoXjRQbqfn3ETNL9ZvQuarwAYC9Ix5MxUrS5ag\nOmfjc8bfkpYDFAXRXmdKNISJmtCebX2kDrpP8Bdasx7Fzsx59cEUHCl2aJOWXc7R\n5m3juOVL1HUxjQIDAQABoyAwHjAcBgNVHREEFTATghFnYXRld2F5Ki5jbWl4LnJp\ncDANBgkqhkiG9w0BAQUFAAOCAQEAMu3xoc2LW2UExAAIYYWEETggLNrlGonxteSu\njuJjOR+ik5SVLn0lEu22+z+FCA7gSk9FkWu+v9qnfOfm2Am+WKYWv3dJ5RypW/hD\nNXkOYxVJNYFxeShnHohNqq4eDKpdqSxEcuErFXJdLbZP1uNs4WIOKnThgzhkpuy7\ntZRosvOF1X5uL1frVJzHN5jASEDAa7hJNmQ24kh+ds/Ge39fGD8pK31CWhnIXeDo\nvKD7wivi/gSOBtcRWWLvU8SizZkS3hgTw0lSOf5geuzvasCEYlqrKFssj6cTzbCB\nxy3ra3WazRTNTW4TmkHlCUC9I3oWTTxw5iQxF/I2kQQnwR7L3w==\n-----END CERTIFICATE-----"}, {"Address": "52.25.219.38", "Tls_certificate": "-----BEGIN CERTIFICATE-----\nMIIDgTCCAmmgAwIBAgIJAKLdZ8UigIAeMA0GCSqGSIb3DQEBBQUAMG8xCzAJBgNV\nBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQx\nGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjEaMBgGA1UEAwwRZ2F0ZXdheSou\nY21peC5yaXAwHhcNMTkwMzA1MTgzNTU0WhcNMjkwMzAyMTgzNTU0WjBvMQswCQYD\nVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJQ2xhcmVtb250\nMRswGQYDVQQKDBJQcml2YXRlZ3JpdHkgQ29ycC4xGjAYBgNVBAMMEWdhdGV3YXkq\nLmNtaXgucmlwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9+AaxwDP\nxHbhLmn4HoZu0oUM48Qufc6T5XEZTrpMrqJAouXk+61Jc0EFH96/sbj7VyvnXPRo\ngIENbk2Y84BkB9SkRMIXya/gh9dOEDSgnvj/yg24l3bdKFqBMKiFg00PYB30fU+A\nbe3OI/le0I+v++RwH2AV0BMq+T6PcAGjCC1Q1ZB0wP9/VqNMWq5lbK9wD46IQiSi\n+SgIQeE7HoiAZXrGO0Y7l9P3+VRoXjRQbqfn3ETNL9ZvQuarwAYC9Ix5MxUrS5ag\nOmfjc8bfkpYDFAXRXmdKNISJmtCebX2kDrpP8Bdasx7Fzsx59cEUHCl2aJOWXc7R\n5m3juOVL1HUxjQIDAQABoyAwHjAcBgNVHREEFTATghFnYXRld2F5Ki5jbWl4LnJp\ncDANBgkqhkiG9w0BAQUFAAOCAQEAMu3xoc2LW2UExAAIYYWEETggLNrlGonxteSu\njuJjOR+ik5SVLn0lEu22+z+FCA7gSk9FkWu+v9qnfOfm2Am+WKYWv3dJ5RypW/hD\nNXkOYxVJNYFxeShnHohNqq4eDKpdqSxEcuErFXJdLbZP1uNs4WIOKnThgzhkpuy7\ntZRosvOF1X5uL1frVJzHN5jASEDAa7hJNmQ24kh+ds/Ge39fGD8pK31CWhnIXeDo\nvKD7wivi/gSOBtcRWWLvU8SizZkS3hgTw0lSOf5geuzvasCEYlqrKFssj6cTzbCB\nxy3ra3WazRTNTW4TmkHlCUC9I3oWTTxw5iQxF/I2kQQnwR7L3w==\n-----END CERTIFICATE-----"}, {"Address": "52.41.80.104", "Tls_certificate": "-----BEGIN CERTIFICATE-----\nMIIDgTCCAmmgAwIBAgIJAKLdZ8UigIAeMA0GCSqGSIb3DQEBBQUAMG8xCzAJBgNV\nBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQx\nGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjEaMBgGA1UEAwwRZ2F0ZXdheSou\nY21peC5yaXAwHhcNMTkwMzA1MTgzNTU0WhcNMjkwMzAyMTgzNTU0WjBvMQswCQYD\nVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJQ2xhcmVtb250\nMRswGQYDVQQKDBJQcml2YXRlZ3JpdHkgQ29ycC4xGjAYBgNVBAMMEWdhdGV3YXkq\nLmNtaXgucmlwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9+AaxwDP\nxHbhLmn4HoZu0oUM48Qufc6T5XEZTrpMrqJAouXk+61Jc0EFH96/sbj7VyvnXPRo\ngIENbk2Y84BkB9SkRMIXya/gh9dOEDSgnvj/yg24l3bdKFqBMKiFg00PYB30fU+A\nbe3OI/le0I+v++RwH2AV0BMq+T6PcAGjCC1Q1ZB0wP9/VqNMWq5lbK9wD46IQiSi\n+SgIQeE7HoiAZXrGO0Y7l9P3+VRoXjRQbqfn3ETNL9ZvQuarwAYC9Ix5MxUrS5ag\nOmfjc8bfkpYDFAXRXmdKNISJmtCebX2kDrpP8Bdasx7Fzsx59cEUHCl2aJOWXc7R\n5m3juOVL1HUxjQIDAQABoyAwHjAcBgNVHREEFTATghFnYXRld2F5Ki5jbWl4LnJp\ncDANBgkqhkiG9w0BAQUFAAOCAQEAMu3xoc2LW2UExAAIYYWEETggLNrlGonxteSu\njuJjOR+ik5SVLn0lEu22+z+FCA7gSk9FkWu+v9qnfOfm2Am+WKYWv3dJ5RypW/hD\nNXkOYxVJNYFxeShnHohNqq4eDKpdqSxEcuErFXJdLbZP1uNs4WIOKnThgzhkpuy7\ntZRosvOF1X5uL1frVJzHN5jASEDAa7hJNmQ24kh+ds/Ge39fGD8pK31CWhnIXeDo\nvKD7wivi/gSOBtcRWWLvU8SizZkS3hgTw0lSOf5geuzvasCEYlqrKFssj6cTzbCB\nxy3ra3WazRTNTW4TmkHlCUC9I3oWTTxw5iQxF/I2kQQnwR7L3w==\n-----END CERTIFICATE-----"}], "nodes": [{"Id": [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "Dsa_public_key": "-----BEGIN PUBLIC KEY-----\nMIIDNDCCAiwCggEBAJ22+1lRtmu2/h4UDx0s5VAjdBYf1lON8WSCGGQvC1xIyPek\nGq36GHMkuHZ0+hgisA8ez4E2lD18VXVyZOWhpE/+AS6ZNuAMHT6TELAcfReYBdMF\niyqfS7b5cWv+YRfGtbPMTZvjQRBK1KgK1slOAF9LmT4U8JHrUXQ78zBQw43iNVZ+\nGzTD1qXAzqoaDzaCE8PRmEPQtLCdy5/HLTnI3kHxvxTUu0Vjyig3FiHK0zJLai05\nIUW+v6x0iAUjb1yi/pK4cc2PnDbTKStVCcqMqneirfx7/XfdpvcRJadFb+oVPkMy\nVqImHGoG7TaTeX55lfrVqrvPvj7aJ0HjdUBK4lsCIQDywxGTdM52yTVpkLRlN0oX\n8j+e01CJvZafYcbd6ZmMHwKCAQBcf/awb48UP+gohDNJPkdpxNmIrOW+JaDiSAln\nBxbGE9ewzuaTL4+qfETSyyRSPaU/vk9uw1lYktGqWMQyigbEahVmLn6qcDod7Pi7\nstBdvi65VsFCozhmHRBGHA0TVHIIUFfzSUMJ/6c8YR94syrbtXQMNhyfNb6QmX2y\nAU4u9apheC9Sq+uL1kMsTdCXvFQjsoXa+2DcNk6BYfSio1rKOhCxxNIDzHakcKM6\n/cvdkpWYWavYtW4XJSUteOrGbnG6muPx3SSHGZh0OTzU2DIYaABlR2Dh40wJ5NFV\nF5+ewNxEc/mWvc5u7Ryr7YtvEW962c9QXfD5mONKsnUUsP/nAoIBAERwUmUlL9YP\nq6MSn+bUr6qNZPsVYoQAo8nTjZWiuSjJa2XWnh7sftnISWkwkiiRxo7qfq3sAiD5\nB8+tM6kONeICBXukldXJerxoVBspYa+RiPuDWy2pwGRDBpfty3QqJOpu5g2ThYFJ\nD5Xu0yCuX8ZJRj33nliI8dQgKdQQva6p2VuXzyRT8LwXMfRwLuSB6Schc9mF8C\nkWCb4m0ujlEKe1xKoKt2zG9b1o7XyaVhxguSUAuEznifMzsEUfuONJOy+XoQELex\nF0wvLzNzABcyxkM3lx52uG41mKgJiV6Z0ZyuBRvt+V3VL/38tPn9lsTaFi8N6/IH\nRyy0bWP5s44=\n-----END PUBLIC KEY-----\n", "Address": "18.237.147.105", "Tls_certificate": "-----BEGIN CERTIFICATE-----MIIDbDCCAlSgAwIBAgIJAOUNtZneIYECMA0GCSqGSIb3DQEBBQUAMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQxGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjETMBEGA1UEAwwKKi5jbWl4LnJpcDAeFwOTAzMDUxODM1NDNaFw0yOTAzMDIxODM1NDNaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQxGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjETMBEGA1UEAwwKKi5jbWl4LnJpcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPP0WyVkfZA/CEd2DgKpcudn0oDhDwsjmx8LBDWsUgQzyLrFiVigfUmUefknUH3dTJjmiJtGqLsayCnWdqWLHPJYvFfsWYW0IGF93UG/4N5UAWO4okC3CYgKSi4ekpfw2zgZq0gmbzTnXcHF9gfmQ7jJUKSEtJPSNzXq+PZeJTC9zJAb4Lj8QzH18rDM8DaL2y1ns0Y2Hu0edBFn/OqavBJKb/uAm3AEjqeOhC7EQUjVamWlTBPt40+B/6aFJX5BYm2JFkRsGBIyBVL46MvC02MgzTT9bJIJfwqmBaTruwemNgzGu7Jk03hqqS1TUEvSI6/x8bVoba3orcKkf9HsDjECAwEAAaMZMBcwFQYDVR0RBA4wDIIKKi5jbWl4LnJpcDANBgkqhkiG9w0BAQUFAAOCAQEAneUocN4AbcQAC1+b3To8u5UGdaGxhcGyZBlAoenRVdjXK3lTjsMdMWb4QctgNfIfU/zuUn2mxTmF/ekP0gCCgtleZr9+DYKU5hlXk8K10uKxGD6EvoiXZzlfeUuotgp2qvI3ysOm/hvCfyEkqhfHtbxjV7j7v7eQFPbvNaXbLa0yr4C4vMK/Z09Ui9JrZ/Z4cyIkxfC6/rOqAirSdIp09EGiw7GM8guHyggE4IiZrDslT8V3xIl985cbCxSxeW1RtgH4rdEXuVe9+31oJhmXOE9ux2jCop9tEJMgWg7HStrJ5plPbb+HmjoX3nBO04E56m52PyzMNV+2N21IPppKwA==-----END CERTIFICATE-----"}, {"Id": [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "Dsa_public_key": "-----BEGIN PUBLIC KEY-----\nMIIDNDCCAiwCggEBAJ22+1lRtmu2/h4UDx0s5VAjdBYf1lON8WSCGGQvC1xIyPek\nGq36GHMkuHZ0+hgisA8ez4E2lD18VXVyZOWhpE/+AS6ZNuAMHT6TELAcfReYBdMF\niyqfS7b5cWv+YRfGtbPMTZvjQRBK1KgK1slOAF9LmT4U8JHrUXQ78zBQw43iNVZ+\nGzTD1qXAzqoaDzaCE8PRmEPQtLCdy5/HLTnI3kHxvxTUu0Vjyig3FiHK0zJLai05\nIUW+v6x0iAUjb1yi/pK4cc2PnDbTKStVCcqMqneirfx7/XfdpvcRJadFb+oVPkMy\nVqImHGoG7TaTeX55lfrVqrvPvj7aJ0HjdUBK4lsCIQDywxGTdM52yTVpkLRlN0oX\n8j+e01CJvZafYcbd6ZmMHwKCAQBcf/awb48UP+gohDNJPkdpxNmIrOW+JaDiSAln\nBxbGE9ewzuaTL4+qfETSyyRSPaU/vk9uw1lYktGqWMQyigbEahVmLn6qcDod7Pi7\nstBdvi65VsFCozhmHRBGHA0TVHIIUFfzSUMJ/6c8YR94syrbtXQMNhyfNb6QmX2y\nAU4u9apheC9Sq+uL1kMsTdCXvFQjsoXa+2DcNk6BYfSio1rKOhCxxNIDzHakcKM6\n/cvdkpWYWavYtW4XJSUteOrGbnG6muPx3SSHGZh0OTzU2DIYaABlR2Dh40wJ5NFV\nF5+ewNxEc/mWvc5u7Ryr7YtvEW962c9QXfD5mONKsnUUsP/nAoIBAFbADcqA8KQh\nxzgylW6VS1dYYelO5DjPZVVSjfdcbj1twu4ZHDNZLOexpv4nGY8xS6vesELXcVOR\n/CHXgh/3byBZYm0zkrBi/FsJJ3nP2uZ1+QCRldI2KzqcLOWH/CAYj8koork9k1Dp\nFq7rMSDgw4pktqvFj9Eev8dSZuRnoCfZbt/6vxi1r30AYAjDYOwcysqcVyUa1tPa\nLEh3JksttXUCd5cvfqatWedTs5Vxo7ICW1toGBHABYvSJkwK0YFfi5RLw+Oda1sA\njJ+aLcIxQjrpoRC2alXCdwmZXVb+O6zluQctw6LJjt4J704ueSvR4VNNhr0uLYGW\nk7e+WoQCS98=\n-----END PUBLIC KEY-----\n", "Address": "52.11.136.238", "Tls_certificate": "-----BEGIN CERTIFICATE-----MIIDbDCCAlSgAwIBAgIJAOUNtZneIYECMA0GCSqGSIb3DQEBBQUAMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQxGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjETMBEGA1UEAwwKKi5jbWl4LnJpcDAeFwOTAzMDUxODM1NDNaFw0yOTAzMDIxODM1NDNaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQxGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjETMBEGA1UEAwwKKi5jbWl4LnJpcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPP0WyVkfZA/CEd2DgKpcudn0oDhDwsjmx8LBDWsUgQzyLrFiVigfUmUefknUH3dTJjmiJtGqLsayCnWdqWLHPJYvFfsWYW0IGF93UG/4N5UAWO4okC3CYgKSi4ekpfw2zgZq0gmbzTnXcHF9gfmQ7jJUKSEtJPSNzXq+PZeJTC9zJAb4Lj8QzH18rDM8DaL2y1ns0Y2Hu0edBFn/OqavBJKb/uAm3AEjqeOhC7EQUjVamWlTBPt40+B/6aFJX5BYm2JFkRsGBIyBVL46MvC02MgzTT9bJIJfwqmBaTruwemNgzGu7Jk03hqqS1TUEvSI6/x8bVoba3orcKkf9HsDjECAwEAAaMZMBcwFQYDVR0RBA4wDIIKKi5jbWl4LnJpcDANBgkqhkiG9w0BAQUFAAOCAQEAneUocN4AbcQAC1+b3To8u5UGdaGxhcGyZBlAoenRVdjXK3lTjsMdMWb4QctgNfIfU/zuUn2mxTmF/ekP0gCCgtleZr9+DYKU5hlXk8K10uKxGD6EvoiXZzlfeUuotgp2qvI3ysOm/hvCfyEkqhfHtbxjV7j7v7eQFPbvNaXbLa0yr4C4vMK/Z09Ui9JrZ/Z4cyIkxfC6/rOqAirSdIp09EGiw7GM8guHyggE4IiZrDslT8V3xIl985cbCxSxeW1RtgH4rdEXuVe9+31oJhmXOE9ux2jCop9tEJMgWg7HStrJ5plPbb+HmjoX3nBO04E56m52PyzMNV+2N21IPppKwA==-----END CERTIFICATE-----"}, {"Id": [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], "Dsa_public_key": "-----BEGIN PUBLIC KEY-----\nMIIDNTCCAiwCggEBAJ22+1lRtmu2/h4UDx0s5VAjdBYf1lON8WSCGGQvC1xIyPek\nGq36GHMkuHZ0+hgisA8ez4E2lD18VXVyZOWhpE/+AS6ZNuAMHT6TELAcfReYBdMF\niyqfS7b5cWv+YRfGtbPMTZvjQRBK1KgK1slOAF9LmT4U8JHrUXQ78zBQw43iNVZ+\nGzTD1qXAzqoaDzaCE8PRmEPQtLCdy5/HLTnI3kHxvxTUu0Vjyig3FiHK0zJLai05\nIUW+v6x0iAUjb1yi/pK4cc2PnDbTKStVCcqMqneirfx7/XfdpvcRJadFb+oVPkMy\nVqImHGoG7TaTeX55lfrVqrvPvj7aJ0HjdUBK4lsCIQDywxGTdM52yTVpkLRlN0oX\n8j+e01CJvZafYcbd6ZmMHwKCAQBcf/awb48UP+gohDNJPkdpxNmIrOW+JaDiSAln\nBxbGE9ewzuaTL4+qfETSyyRSPaU/vk9uw1lYktGqWMQyigbEahVmLn6qcDod7Pi7\nstBdvi65VsFCozhmHRBGHA0TVHIIUFfzSUMJ/6c8YR94syrbtXQMNhyfNb6QmX2y\nAU4u9apheC9Sq+uL1kMsTdCXvFQjsoXa+2DcNk6BYfSio1rKOhCxxNIDzHakcKM6\n/cvdkpWYWavYtW4XJSUteOrGbnG6muPx3SSHGZh0OTzU2DIYaABlR2Dh40wJ5NFV\nF5+ewNxEc/mWvc5u7Ryr7YtvEW962c9QXfD5mONKsnUUsP/nAoIBAQCN19tTnkS3\nitBQXXR/h8OKl+rliFBLgO6h6GvZL4yQDZFtBAOmkrs3wLoDroJRGCeqz/IUb+JF\njslEr/mpm2kcmK77hr535dq7HsWz1fFl9YyGTaOH055FLSV9QEPAV9j3zWADdQ1v\nuSQll+QfWi6lIibWV4HNQ2ywRFoOY8OBLCJB90UXLeJpaPanpqiM8hjda2VGRDbi\nIixEE2lCOWITydiz2DmvXrLhVGF49+g5MDwbWO65dmasCe//Ff6Z4bJ6n049xv\nVtac8nX6FO3eBsV5d+rG6HZXSG3brCKRCSKYCTX1IkTSiutYxYqvwaluoCjOakh0\nKkqvQ8IeVZ+B\n-----END PUBLIC KEY-----\n", "Address": "34.213.79.31", "Tls_certificate": "-----BEGIN CERTIFICATE-----MIIDbDCCAlSgAwIBAgIJAOUNtZneIYECMA0GCSqGSIb3DQEBBQUAMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQxGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjETMBEGA1UEAwwKKi5jbWl4LnJpcDAeFwOTAzMDUxODM1NDNaFw0yOTAzMDIxODM1NDNaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQxGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjETMBEGA1UEAwwKKi5jbWl4LnJpcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPP0WyVkfZA/CEd2DgKpcudn0oDhDwsjmx8LBDWsUgQzyLrFiVigfUmUefknUH3dTJjmiJtGqLsayCnWdqWLHPJYvFfsWYW0IGF93UG/4N5UAWO4okC3CYgKSi4ekpfw2zgZq0gmbzTnXcHF9gfmQ7jJUKSEtJPSNzXq+PZeJTC9zJAb4Lj8QzH18rDM8DaL2y1ns0Y2Hu0edBFn/OqavBJKb/uAm3AEjqeOhC7EQUjVamWlTBPt40+B/6aFJX5BYm2JFkRsGBIyBVL46MvC02MgzTT9bJIJfwqmBaTruwemNgzGu7Jk03hqqS1TUEvSI6/x8bVoba3orcKkf9HsDjECAwEAAaMZMBcwFQYDVR0RBA4wDIIKKi5jbWl4LnJpcDANBgkqhkiG9w0BAQUFAAOCAQEAneUocN4AbcQAC1+b3To8u5UGdaGxhcGyZBlAoenRVdjXK3lTjsMdMWb4QctgNfIfU/zuUn2mxTmF/ekP0gCCgtleZr9+DYKU5hlXk8K10uKxGD6EvoiXZzlfeUuotgp2qvI3ysOm/hvCfyEkqhfHtbxjV7j7v7eQFPbvNaXbLa0yr4C4vMK/Z09Ui9JrZ/Z4cyIkxfC6/rOqAirSdIp09EGiw7GM8guHyggE4IiZrDslT8V3xIl985cbCxSxeW1RtgH4rdEXuVe9+31oJhmXOE9ux2jCop9tEJMgWg7HStrJ5plPbb+HmjoX3nBO04E56m52PyzMNV+2N21IPppKwA==-----END CERTIFICATE-----"}], "registration": {"Dsa_public_key": "-----BEGIN PUBLIC KEY-----\nMIIDNDCCAiwCggEBAJ22+1lRtmu2/h4UDx0s5VAjdBYf1lON8WSCGGQvC1xIyPek\nGq36GHMkuHZ0+hgisA8ez4E2lD18VXVyZOWhpE/+AS6ZNuAMHT6TELAcfReYBdMF\niyqfS7b5cWv+YRfGtbPMTZvjQRBK1KgK1slOAF9LmT4U8JHrUXQ78zBQw43iNVZ+\nGzTD1qXAzqoaDzaCE8PRmEPQtLCdy5/HLTnI3kHxvxTUu0Vjyig3FiHK0zJLai05\nIUW+v6x0iAUjb1yi/pK4cc2PnDbTKStVCcqMqneirfx7/XfdpvcRJadFb+oVPkMy\nVqImHGoG7TaTeX55lfrVqrvPvj7aJ0HjdUBK4lsCIQDywxGTdM52yTVpkLRlN0oX\n8j+e01CJvZafYcbd6ZmMHwKCAQBcf/awb48UP+gohDNJPkdpxNmIrOW+JaDiSAln\nBxbGE9ewzuaTL4+qfETSyyRSPaU/vk9uw1lYktGqWMQyigbEahVmLn6qcDod7Pi7\nstBdvi65VsFCozhmHRBGHA0TVHIIUFfzSUMJ/6c8YR94syrbtXQMNhyfNb6QmX2y\nAU4u9apheC9Sq+uL1kMsTdCXvFQjsoXa+2DcNk6BYfSio1rKOhCxxNIDzHakcKM6\n/cvdkpWYWavYtW4XJSUteOrGbnG6muPx3SSHGZh0OTzU2DIYaABlR2Dh40wJ5NFV\nF5+ewNxEc/mWvc5u7Ryr7YtvEW962c9QXfD5mONKsnUUsP/nAoIBAAlELnrXLG0s\n4yAAn7IsVWwY7swDnbBcsIF2cnef4tjm/nNwrFKp5AxYqgeXCiJM8VkyJrotWG50\nnXQwMCR6BsvYrlVt/RmQvR8BSrir62uSLK7hMKm7dXnFvtyFtjp91UwTRbIjxhUQ\nGYnhAzrkCDWo1m54ysqXEGlrVwvRXrCAXiLKPiTEIS+B4GFH9W26SwBxhFLNYSUk\nZZ7+4qwMf9aTu7kIpXTP3hNIyRCjtuZvo5SnymtbLARwTP943hW8MOj0+Ege+m1P\ntey6rkMUGQ86cgK9/7+7Jb+EwW5UxdQtFPUFeNKdQ6zDPS6qbliecUrsc12tdgeg\nhQyuMbyKUuo=\n-----END PUBLIC KEY-----\n", "Address": "registration.default.cmix.rip", "Tls_certificate": "-----BEGIN CERTIFICATE-----MIIDkDCCAnigAwIBAgIJAJnjosuSsP7gMA0GCSqGSIb3DQEBBQUAMHQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQxGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjEfMB0GA1UEAwwWcmVnaXN0cmF0aW9uKi5jbWl4LnJpcDAeFwOTAzMDUyMTQ5NTZaFw0yOTAzMDIyMTQ5NTZaMHQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDbGFyZW1vbnQxGzAZBgNVBAoMElByaXZhdGVncml0eSBDb3JwLjEfMB0GA1UEAwwWcmVnaXN0cmF0aW9uKi5jbWl4LnJpcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOQKvqjdh35o+MECBhCwopJzPlQNmq2iPbewRNtI02bUNK3kLQUbFlYdzNGZS4GYXGc5O+jdi8Slx82r1kdjz5PPCNFBARIsOP/L8r3DGeW+yeJdgBZjm1s3ylkamt4Ajiq/bNjysS6L/WSOp+sVumDxtBEzO/UTU1O6QRnzUphLaiWENmErGvsH0CZVq38Ia58k/QjCAzpUcYi4j2l1fb07xqFcQD8H6SmUM297UyQosDrp8ukdIo31Koxr4XDnnNNsYStC26tzHMeKuJ2Wl+3YzsSyflfM2YEcKE31sqB9DS36UkJ8J84eLsHNImGg3WodFAviDB67+jXDbB30NkMCAwEAAaMlMCMwIQYDVR0RBBowGIIWcmVnaXN0cmF0aW9uKi5jbWl4LnJpcDANBgkqhkiG9w0BAQUFAAOCAQEAF9mNzk+g+o626Rllt3f3/1qIyYQrYJ0BjSWCKYEFMCgZ4JibAJjAvIajhVYERtltffM+YKcdE2kTpdzJ0YJuUnRfuv6sVnXlVVugUUnd4IOigmjbCdM32k170CYMm0aiwGxl4FrNa8ei7AIax/s1n+sqWq3HeW5LXjnoVb+s3HeCWIuLfcgrurfye8FnNhy14HFzxVYYefIKmL+DPlcGGGm/PPYt3u4a2+rP3xaihc65dTa0u5tf/XPXtPxTDPFj2JeQDFxo7QRREbPD89CtYnwuP937CrkvCKrL0GkW1FViXKqZY9F5uhxrvLIpzhbNrs/EbtweY35XGLDCCMkg==-----END CERTIFICATE-----"}, "udb": {"Id": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3], "Dsa_public_key": "-----BEGIN PUBLIC KEY-----\nMIIDNDCCAiwCggEBAJ22+1lRtmu2/h4UDx0s5VAjdBYf1lON8WSCGGQvC1xIyPek\nGq36GHMkuHZ0+hgisA8ez4E2lD18VXVyZOWhpE/+AS6ZNuAMHT6TELAcfReYBdMF\niyqfS7b5cWv+YRfGtbPMTZvjQRBK1KgK1slOAF9LmT4U8JHrUXQ78zBQw43iNVZ+\nGzTD1qXAzqoaDzaCE8PRmEPQtLCdy5/HLTnI3kHxvxTUu0Vjyig3FiHK0zJLai05\nIUW+v6x0iAUjb1yi/pK4cc2PnDbTKStVCcqMqneirfx7/XfdpvcRJadFb+oVPkMy\nVqImHGoG7TaTeX55lfrVqrvPvj7aJ0HjdUBK4lsCIQDywxGTdM52yTVpkLRlN0oX\n8j+e01CJvZafYcbd6ZmMHwKCAQBcf/awb48UP+gohDNJPkdpxNmIrOW+JaDiSAln\nBxbGE9ewzuaTL4+qfETSyyRSPaU/vk9uw1lYktGqWMQyigbEahVmLn6qcDod7Pi7\nstBdvi65VsFCozhmHRBGHA0TVHIIUFfzSUMJ/6c8YR94syrbtXQMNhyfNb6QmX2y\nAU4u9apheC9Sq+uL1kMsTdCXvFQjsoXa+2DcNk6BYfSio1rKOhCxxNIDzHakcKM6\n/cvdkpWYWavYtW4XJSUteOrGbnG6muPx3SSHGZh0OTzU2DIYaABlR2Dh40wJ5NFV\nF5+ewNxEc/mWvc5u7Ryr7YtvEW962c9QXfD5mONKsnUUsP/nAoIBACvR2lUslz3D\nB/MUo0rHVIHVkhVJCxNjtgTOYgJ9ckArSXQbYzr/fcigcNGjUO2LbK5NFp9GK43C\nrLxMUnJ9nkyIVPaWvquJFZItjcDK3NiNGyD4XyM0eRj4dYeSxQM48hvFbmtbjlXn\n9SQTnGIlr1XnTI4RVHZSQOL6kFJIaLw6wYrQ4w08Ng+p45brp5ercAHnLiftNUWP\nqROhQkdSEpS9LEwfotUSY1jP2AhQfaIMxaeXsZuTU1IYvdhMFRL3DR0r5Ww2Upf8\ng0Ace0mtnsUQ2OG+7MTh2jYIEWRjvuoe3RCz603ujW6g7BfQ1H7f4YFwc5xOOJ3u\nr4dj49dCCjc=\n-----END PUBLIC KEY-----\n"}, "E2e": {"Prime": "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", "Small_prime": "7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68948127044533E63A0105DF531D89CD9128A5043CC71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6F71C35FDAD44CFD2D74F9208BE258FF324943328F6722D9EE1003E5C50B1DF82CC6D241B0E2AE9CD348B1FD47E9267AFC1B2AE91EE51D6CB0E3179AB1042A95DCF6A9483B84B4B36B3861AA7255E4C0278BA3604650C10BE19482F23171B671DF1CF3B960C074301CD93C1D17603D147DAE2AEF837A62964EF15E5FB4AAC0B8C1CCAA4BE754AB5728AE9130C4C7D02880AB9472D455655347FFFFFFFFFFFFFFF", "Generator": "02"}, "CMIX": {"Prime": "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", "Small_prime": "7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68948127044533E63A0105DF531D89CD9128A5043CC71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6F71C35FDAD44CFD2D74F9208BE258FF324943328F6722D9EE1003E5C50B1DF82CC6D241B0E2AE9CD348B1FD47E9267AFC1B2AE91EE51D6CB0E3179AB1042A95DCF6A9483B84B4B36B3861AA7255E4C0278BA3604650C10BE19482F23171B671DF1CF3B960C074301CD93C1D17603D147DAE2AEF837A62964EF15E5FB4AAC0B8C1CCAA4BE754AB5728AE9130C4C7D02880AB9472D455655347FFFFFFFFFFFFFFF", "Generator": "02"}}`

// Tests that VerifyNDF() correctly verifies the NDF signature.
func TestVerifyNDF(t *testing.T) {
	// Load TLS private key
	privKey, err := rsa.LoadPrivateKeyFromPem([]byte("-----BEGIN PRIVATE KEY-----\n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\nOaRA5ZbdE7g7vxKRV36jT3wvD7W+\n-----END PRIVATE KEY-----\n"))
	if err != nil || privKey == nil {
		t.Error("Failed to load privKey\n")
	}

	// Sign the NDF
	ndfJSON, _, _ := ndf.DecodeNDF(ExampleJSON + "\n")
	rsaHash := crypto.SHA256.New()
	rsaHash.Write(ndfJSON.Serialize())
	signature, _ := rsa.Sign(
		rand.Reader, privKey, crypto.SHA256, rsaHash.Sum(nil), nil)

	// Print error on panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("VerifyNDF() panicked when it was not supposed to"+
				"\n\treceived: %#v\n\texpected: %#v", r, nil)
		}
	}()

	// Compose network definition string
	ndfString := ExampleJSON + "\n" + base64.StdEncoding.EncodeToString(signature)

	// Run VerifyNDF()
	fmt.Println(ndfString)
	ndfJSONOutput := VerifyNDF(ndfString, "-----BEGIN CERTIFICATE-----\n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\n-----END CERTIFICATE-----\n")

	// Check that the output is the expected NetworkDefinition structure
	if !reflect.DeepEqual(ndfJSONOutput, ndfJSON) {
		t.Errorf("VerifyNDF() did not output the correct "+
			"NetworkDefinition structure"+
			"\n\treceived: %#v\n\texpected: %#v",
			ndfJSONOutput, ndfJSON)
	}
}

// Tests that VerifyNDF() panics when given the incorrect RSA public key.
func TestVerifyNDF_ErrPublicKey(t *testing.T) {
	// Generate RSA private key and fake RSA public key
	// Size of 768 is unsafe, but allows the test to run faster
	privateKey, _ := rsa.GenerateKey(rand.Reader, 768)

	privateKey2, _ := rsa.GenerateKey(rand.Reader, 768)
	publicKey := &rsa.PublicKey{PublicKey: privateKey2.PublicKey}
	publicKeyBytes := rsa.CreatePublicKeyPem(publicKey)

	// Sign the NDF
	ndfJSON, _, _ := ndf.DecodeNDF(ExampleJSON + "\n")
	opts := rsa.NewDefaultOptions()
	rsaHash := opts.Hash.New()
	rsaHash.Write(ndfJSON.Serialize())
	signature, _ := rsa.Sign(
		rand.Reader, privateKey, opts.Hash, rsaHash.Sum(nil), nil)

	// Print error on no panic
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("VerifyNDF() did not panic when expected when the "+
				"public key is invalid"+
				"\n\treceived: %#v\n\texpected: %#v",
				r, "Could not verify NDF: crypto/rsa: verification error")
		}
	}()

	// Compose network definition string
	ndfString := ExampleJSON + "\n" + base64.StdEncoding.EncodeToString(signature)

	// Run VerifyNDF()
	VerifyNDF(ndfString, string(publicKeyBytes))
}

// Tests that VerifyNDF() panics when given an invalid NDF string.
func TestVerifyNDF_ErrInvalidNDF(t *testing.T) {
	// Generate RSA private key and fake RSA public key
	// Size of 768 is unsafe, but allows the test to run faster
	privateKey, _ := rsa.GenerateKey(rand.Reader, 768)

	privateKey2, _ := rsa.GenerateKey(rand.Reader, 768)
	publicKey := &rsa.PublicKey{PublicKey: privateKey2.PublicKey}
	publicKeyBytes := rsa.CreatePublicKeyPem(publicKey)

	// Sign the NDF
	ndfJSON, _, _ := ndf.DecodeNDF(ExampleJSON + "\n")
	opts := rsa.NewDefaultOptions()
	rsaHash := opts.Hash.New()
	rsaHash.Write(ndfJSON.Serialize())
	signature, _ := rsa.Sign(
		rand.Reader, privateKey, opts.Hash, rsaHash.Sum(nil), nil)

	// Print error on no panic
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("VerifyNDF() did not panic when expected when given "+
				"invalid NDF"+
				"\n\treceived: %#v\n\texpected: %#v",
				r, "Could not decode NDF: unexpected end of JSON input")
		}
	}()

	// Compose network definition string
	ndfString := "   \n" + base64.StdEncoding.EncodeToString(signature)

	// Run VerifyNDF()
	VerifyNDF(ndfString, string(publicKeyBytes))
}

// Tests that VerifyNDF() correctly outputs a NetworkDefinition structure and
// skips verifying the signature when the public key is empty.
func TestVerifyNDF_EmptyPublicKey(t *testing.T) {
	// Generate RSA private and public keys
	// Size of 768 is unsafe, but allows the test to run faster
	privateKey, _ := rsa.GenerateKey(rand.Reader, 768)

	// Sign the NDF
	ndfJSON, _, _ := ndf.DecodeNDF(ExampleJSON + "\n")
	opts := rsa.NewDefaultOptions()
	rsaHash := opts.Hash.New()
	rsaHash.Write(ndfJSON.Serialize())
	signature, _ := rsa.Sign(
		rand.Reader, privateKey, opts.Hash, rsaHash.Sum(nil), nil)

	// Compose network definition string
	ndfString := ExampleJSON + "\n" + base64.StdEncoding.EncodeToString(signature)

	// Run VerifyNDF()
	ndfJSONOutput := VerifyNDF(ndfString, "")

	// Check that the output is the expected NetworkDefinition structure
	if !reflect.DeepEqual(ndfJSONOutput, ndfJSON) {
		t.Errorf("VerifyNDF() did not output the correct "+
			"NetworkDefinition structure"+
			"\n\treceived: %#v\n\texpected: %#v",
			ndfJSONOutput, ndfJSON)
	}
}
