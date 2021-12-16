﻿namespace CustomSha256
{
    using NetworkHost;
    using System.Net;
    using System.Text;

    class Program
    {
        private const string Key1 = "<RSAKeyValue><Modulus>2ulxPTVJiEwYZ8LGtCmZT7bFMs6q/lt2F/nOfjJHAWMB3N9scqFO/ttl69mnR535jqr09MYQQirBUvXlpoVIrCw68I/0eCBzfCRF3C+yCLp4ga6Hj3EpBnKIqJKSg7Q0p0+0/BqYf5hYxtqA4wFip7VZIHPSbPmRjRiF5bfzWk0=</Modulus><Exponent>AQAB</Exponent><P>8/XNGfISCPZyWJl9WPsvdXUQYPVcSYi+xAvXU7cWuIaFO8QPuk8EHlOd4yJUetB7+yCB8Yje/mFg28OCgTFfCw==</P><Q>5bcuPAo3o6/y4jmRIAvc0uWnGoBCd9P+thOUIzbHxh7pv+8vFgSXEAxPNbNYx7xhMeAC1gPbo9+Y0qMKiNnjBw==</Q><DP>Yw8UyAs9/XusdINmnWHpJGVzUBtw7L7kzxAL0AdQ535fzSPQSxNYlcPYIWlIKlJLdW3+tYehHGOIA9RAQps8fw==</DP><DQ>cOdWpxXSgPZSp1Pp+1k5QMK1HfZaNPESKMV4stIS4FKDSt2xQ94frTiPmfI7OXhiQRQ78JpW0rVsNGMEI30L8w==</DQ><InverseQ>Z0E59qZ019Cc3s4hD46Ps9xnnKLLoTd0QpKAS5SzHqjZ16E7Axlzu4KRDMzbV7CODlrkq5O6nbrMO4WwVM7uIg==</InverseQ><D>voa0bvBE6mJIT25/YGhgLbfGE705p51Uv/NEHCOIFxXjlifCjFYGmdu77jSF2dgNTnVOMwd7OQtbLOglEvQn1U16jfcBIPTah9lweMhGMubjNIuUTqXCp7PEbFH1z3A5EW5UATp1kVMGKgfcCi/ohJh8fijGlDxYPaT8WUMqoIU=</D></RSAKeyValue>";
        private const string Key2 = "<RSAKeyValue><Modulus>2TxA9yf9Hu7+iZQkCdZX1VqERi4wap2Ny8Vp9drWZMto957jRzLvSSm49T/mIA7lIwbz70ei5Ti99LjS3AksAkCe6cqDk+xR1eoeNE74AIFDd4NgSm66ANkim3YfPzl8i+YPEE5EF8oYrMwnpB21EUVL6ZBI1IP+zHEYCjuaZ7U=</Modulus><Exponent>AQAB</Exponent><P>6QfYtUDOJ2iTDpzYzOj+l3ylVmyZaQL3vLG9XgV19dtLrFQcAJHABcUh9v9LQuSTqxf6N+bq4lydPkooW4F4ow==</P><Q>7qXWs4U62sezBJILmzeOGgrAX4YvIi29wlm9UkqaJURnN5F2oVBnqNZexBPKGPLRBCvO5cYXI5JgK/GSqmjrxw==</Q><DP>nZe53bJK+OnG8g3urH0xl/8qzYy6HwNryQem2kv1H2TEA3IKUfQ/mWdc9e5m1oFAwGeBx4Z5+MXLbZG3Q1MG4w==</DP><DQ>tbiydKDO4CmQt7o9/EOhgVMOia6z1WLfTE7pSvBj0Fz1++pYWx3O0VHrd4NaMQU1A+gX8/+TPxMHCG87L2gVoQ==</DQ><InverseQ>WfmsWepVhtWYoVWqkzGnPZPd2raGKZHzrtgZaWyxVx6LZ8L1RzcHSYunccqvv49hRvxNhsFs152TRNGYqY+jZw==</InverseQ><D>Ky/sZnZ/vveaiPV3mLERMyxUobMrEvcRqpIrt6Hy/4Tk8F2ZJ517rtrpl3BFqtfrO+R0+HwQaWu3cACSgwYbxlUWqBmoWgaj93muh/8HlFGXPR7PB4SZ1e4qLOzGfMKXiNkCMKblrZt5bhpTMPJfxKDrKrA+REGlmO3vPJwayv0=</D></RSAKeyValue>";
        private const string Key3 = "<RSAKeyValue><Modulus>3VRwzpKbB4vnKm+dXXOj3ETmekWVXSvzgHQsAxfOmlw3SgXU+SvQJnTOPOUK6ToaGGygbJDm2McjsYWOWwDB1zBOPgxwH1/yGCj4mgZPQ7VpFnNRme//TIGDTDWlO+YP2jsoxxWRgsLvHVMLurhe+RDtgtUpdu1uGR4JjdQKIh0=</Modulus><Exponent>AQAB</Exponent><P>9YLHYo0cgDqtDotMu0MUo+TL2XfUOWRZSoMFe3UAgJ/TccJgUZNf19Ha2+yaERF3KFN8HYyZd8g9/JUFvIU+Lw==</P><Q>5skv9H1UFb9YXEOBpcYrlSATr8TZ66X8dceFI8aYPCsQ/WJQu2iSU4dY9eUm88IuItzLB4f1fBHP9e9omAI9cw==</Q><DP>4wUYS9gCZ8xaJB3JSUvhNSAnI6N7mcpiCtWW5y8s1MN1qTa9DBHDyXSi9UQWvvuwfJieJ1DQxINkVkCSul1XPw==</DP><DQ>P2AuQBiOl65FCIktOCXUYA4/+bu4EEMzsfBJeoqV0agN8VcnTl+oFzIK1vPHn5bKbp5tTrMiUaDel+3Xri6nSw==</DQ><InverseQ>deHu3EsY1QPxDKA65Xe8vnAf1Bamd7/Se4+1mz56f3GSNtKshAGo4ls8rNNf6wqF/60xDhCVL4dGKeiF2KmL0g==</InverseQ><D>ZzJA6sBGko0zuoCSMgmCJGjnwakCDJA6l/ESuFp4VVab3OK9O3SnN9cMdi4hGT+i/TJg1l31lKu9Q79O8bV3qxzhdtCLWaUICs0pta8Y5vUv0L7yBEL8VrUe3nxgQtgyNBzs5s0X13QmTNqZCokhdGzlX5gpF0QyN8cR6e7NHw0=</D></RSAKeyValue>";
        private const string Key4 = "<RSAKeyValue><Modulus>rf7K9PXXRNdgDEXeIBjA5nbQ1qjrPn1WumGznNbZZU0PEpLgkjTz78HWY+G5ZTALq0DOVZcXk5uKkmbkTIHUQKdsI5tvxGawJdbdy1Hs7FmHtPxkPpBJ9EZmVEuMkhBuIyxcBacCY8XrVA4zaY/wVQfJSQykInyxKrIo8ShFzBk=</Modulus><Exponent>AQAB</Exponent><P>1JLsND2VEBeGkFiZGV0/2XYltOLvPjWqFBR/8eKMsfjIKpdT1dnJ+2+hfqN6V9+GAUbpzStMQ86FGgQhVjKBqw==</P><Q>0YpOLgYQWH3fAXXGbkDdprmpXA+K2oogKWy3TDUjjYMYL2BUlpblTZzvdlGqrKjFOyneukY3tzDX8B2gNsxtSw==</Q><DP>It/34Jo52moBqazfcUnbL9IyXXrdxVcIkELMuuJwMsKeFF6/YlZYzOeDl0M6zy/czFjWAtMXsAgxzhLfZUTkAQ==</DP><DQ>WTxzSvpeH7GLNU348Z9CReyviXs9ARDt3XZlIVlICM4ZkKOPoookoUcCW/svmlRNmoKcTev1clikvaeAQZYRvQ==</DQ><InverseQ>XbhLWlhhvdIUjfS1NvjeGUTCUzpbhCvI1u8UgYwOKzeevignTeH5uyg2iD2AjCIzN8cEagD+77Y6rEC7ngcJhg==</InverseQ><D>DuAgs+6st9r+AC6c/ft/ynRQCHoqmo4WsxqVQ4xuy6VZ64mZH4bdcBsPXDy5H/iKltqUiWbAgkMjBr87N3tGDRjsiS31IrUwzk1ZMyr5r9+PDz4g3N4nds6J4AD9hCzb+XCJWhsex+KBHQb0duHARE4ZQ+ufV0PZUq7R5nUNCu0=</D></RSAKeyValue>";
        private const string Key5 = "<RSAKeyValue><Modulus>w3pc58qByseG2ynGIF4OSTypvlaT14vV46lOjVP0OPeOdvbVEI3+TWpZla959dz1iGYmdEkPjWFMuR4tGUb5zg0KCYF7QSniZ/Ibs1Ciledi8sZb6JZy89tCzFlEzgGeRobSm5Vr9Nh0uVkxmwr/HDp71g+0d4T8SGhi9Qsl0Z0=</Modulus><Exponent>AQAB</Exponent><P>84Da+UeviPo3kjqeX3ee4utK70zG8szpNo3iGFg1DDSUkkc3r+6W08eV/6XIon3TeBJZ4jUzOP6NA4lqKxw1Bw==</P><Q>zYKNAQ4XyL3vUsjH9G5/5aYcbGx7gctP5tmuXoLGVEt7GLSLxeOW11bjWWRciInGa2jF52Ew3ucv5jgW9khfOw==</Q><DP>Bkht3f6+hb9HDcvbaEUy4VIG5fPKMludLN4uVkh4Xe9BYiDaS/zRAXfl4+nIKoEqoq9+iDqtLqxKwSubhK8+ow==</DP><DQ>VyS6we3F7BuONh5pm56XoTvU5a0CmkEqOounwu/VRb1UD1/PvTQKrHltomRKUKOLfdRJxxmRbZO+3fJ+2iRKLQ==</DQ><InverseQ>6ogNV4I1Tk7vnAfhCSP6IiVSYJ3ixtgYpLfVcbJod9QZu8ByWAaQ3ve4Psh7Ho1ZaoWUBVR1O+cuLz7csRtIXw==</InverseQ><D>uvHG8BYHUrrHCcpFpKbO2tOdMl7yPO2KvJMqgJaNtf1qzfL5iT+CuN7AlhqfdLbASpYGqKdGrFslWNS3JLlwJCWBIfFxsbk9j8DKQLZkNzfOBpsQufkeigEQLZE2yy0zDBvqt/5gvs9o8QQ0uNJcjtZN5APit4lYSkfseEJRgDE=</D></RSAKeyValue>";

        static void Main(string[] args)
        {
            var nodeId = 1;
            var cryptoCore = new CryptoCore(nodeId);

            cryptoCore.InitializeBlockChain();

            var balance = cryptoCore.GetBalance();

            cryptoCore.CreateTransaction(Key2, 5);

            balance = cryptoCore.GetBalance();

            Host host = new Host(IPAddress.Loopback, 11004);

            host.dataReceived += cryptoCore.getDataByHeader;
            host.startListeningInThread();
            host.sendTransaction(Encoding.UTF8.GetBytes("Transaction123"));
        }
    }
}
