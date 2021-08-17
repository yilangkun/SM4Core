using System;
using System.Text;
using System.Text.RegularExpressions;

namespace SM4Core
{
    public class Util
    {
        //private static void Main(string[] args)
        //{
        //    string entxt = encryptDataECB("1111111111111111111", "1qaz2wsx3edc4rfv");
        //    Console.WriteLine(entxt);

        //    //string detxt = decryptDataCBC("OhNrzHGi/O0zFu/I/fhjkw==", "4028b8815ccf2ffe", "EveComF54A3s2D1g");
        //    //Console.WriteLine(detxt);

        //    Console.ReadLine();
        //}

        public static string EncryptDataECB(string plainText, string secretKey)
        {
            try
            {
                Sm4Context ctx = new Sm4Context();
                ctx.isPadding = true;
                ctx.mode = Sm4.SM4_ENCRYPT;

                byte[] keyBytes = Encoding.ASCII.GetBytes(secretKey);

                Sm4 sm4 = new Sm4();
                sm4.sm4SetkeyEnc(ctx, keyBytes);
                byte[] encrypted = sm4.sm4CryptEcb(ctx, Encoding.UTF8.GetBytes(plainText));
                String cipherText = Convert.ToBase64String(encrypted);
                if (cipherText != null && cipherText.Trim().Length > 0)
                {
                    cipherText = Regex.Replace(cipherText, "\\s*|\t|\r|\n", "");
                }
                return cipherText;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }

        public static string DecryptDataECB(string cipherText, string secretKey)
        {
            try
            {
                Sm4Context ctx = new Sm4Context();
                ctx.isPadding = true;
                ctx.mode = Sm4.SM4_DECRYPT;

                byte[] keyBytes = Encoding.ASCII.GetBytes(secretKey);

                Sm4 sm4 = new Sm4();
                sm4.sm4SetkeyDec(ctx, keyBytes);
                byte[] decrypted = sm4.sm4CryptEcb(ctx, Convert.FromBase64String(cipherText));
                return Encoding.UTF8.GetString(decrypted);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }

        public static string DecryptDataCBC(string cipherText, string secretKey, string iv)
        {
            try
            {
                Sm4Context ctx = new Sm4Context();
                ctx.isPadding = true;
                ctx.mode = Sm4.SM4_DECRYPT;

                byte[] keyBytes;
                byte[] ivBytes;

                {
                    keyBytes = Encoding.ASCII.GetBytes(secretKey);
                    ivBytes = Encoding.ASCII.GetBytes(iv);
                }

                Sm4 sm4 = new Sm4();
                sm4.sm4SetkeyDec(ctx, keyBytes);
                byte[] decrypted = sm4.sm4CryptCbc(ctx, ivBytes, Convert.FromBase64String(cipherText));
                return Encoding.UTF8.GetString(decrypted);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }

        public static string EncryptDataCBC(string plainText, string secretKey, string iv)
        {
            try
            {
                Sm4Context ctx = new Sm4Context();
                ctx.isPadding = true;
                ctx.mode = Sm4.SM4_ENCRYPT;

                byte[] keyBytes;
                byte[] ivBytes;

                {
                    keyBytes = Encoding.ASCII.GetBytes(secretKey);
                    ivBytes = Encoding.ASCII.GetBytes(iv);
                }

                Sm4 sm4 = new Sm4();
                sm4.sm4SetkeyEnc(ctx, keyBytes);
                byte[] encrypted = sm4.sm4CryptCbc(ctx, ivBytes, Encoding.UTF8.GetBytes(plainText));
                String cipherText = Convert.ToBase64String(encrypted);
                if (cipherText != null && cipherText.Trim().Length > 0)
                {
                    cipherText = Regex.Replace(cipherText, "\\s*|\t|\r|\n", "");
                }
                return cipherText;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }
    }
}