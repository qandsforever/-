using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using zlib;
using System.Net.Http;
using System.IO;
namespace 网络抓包分析
{
    public static class getIpDataClass
    {
        public static bool getIpDataFromWeb()
        {
            try
            {
                HttpClient client = new System.Net.Http.HttpClient();

                client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/3.0 (compatible;Indy Library)");
                client.DefaultRequestHeaders.Add("Accept", "text/html,*/*");
                MemoryStream ms = new MemoryStream();
                var response = client.GetAsync("http://update.cz88.net/ip/copywrite.rar").Result;
                if (!response.IsSuccessStatusCode) return false;

                response.Content.ReadAsStreamAsync().Result.CopyTo(ms);

                ms.Position = 0;
                byte[] data = ms.ToArray();

                if (data.Length < 24 || Encoding.Default.GetString(data.Take(4).ToArray()) != "CZIP")
                {
                    return false;
                }
                int version = BitConverter.ToInt32(data.Skip(4).Take(4).ToArray(), 0);
                int unknown1 = BitConverter.ToInt32(data.Skip(8).Take(4).ToArray(), 0);
                int size = BitConverter.ToInt32(data.Skip(12).Take(4).ToArray(), 0);
                int unknown2 = BitConverter.ToInt32(data.Skip(16).Take(4).ToArray(), 0);
                int key = BitConverter.ToInt32(data.Skip(20).Take(4).ToArray(), 0);


                response = client.GetAsync("http://update.cz88.net/ip/qqwry.rar").Result;
                if (!response.IsSuccessStatusCode) return false;
                response.Content.ReadAsStreamAsync().Result.CopyTo(ms);
                ms.Position = 0;
                data = ms.ToArray();
                if (data.Length != size) return false;

                byte[] head = new byte[0x200];
                for (int i = 0; i < 0x200; i++)
                {
                    key = (key * 0x805 + 1) & 0xff;
                    head[i] = (byte)((data[i]) ^ key);
                    data[i] = head[i];
                }


                byte[] data1 = deCompressBytes(data);
                File.WriteAllBytes("qqwry.dat", data1);
                
                return true;
            }
            catch( Exception ee)
            {
                return false;
            }
            

        }



        public static void CopyStream(Stream input, Stream output)
        {
            
            byte[] buffer = new byte[32768];
            int len;



            while ((len = input.Read(buffer, 0, 32768)) > 0)
            {
                output.Write(buffer, 0, len);
            }
            output.Flush();
            
        }
        /// <summary>
        /// 压缩字节数组
        /// </summary>
        /// <param name="sourceByte">需要被压缩的字节数组</param>
        /// <returns>压缩后的字节数组</returns>
        private static byte[] compressBytes(byte[] sourceByte)
        {
            MemoryStream inputStream = new MemoryStream(sourceByte);
            Stream outStream = compressStream(inputStream);
            byte[] outPutByteArray = new byte[outStream.Length];
            outStream.Position = 0;
            outStream.Read(outPutByteArray, 0, outPutByteArray.Length);
            outStream.Close();
            inputStream.Close();
            return outPutByteArray;
        }
        /// <summary>
        /// 解压缩字节数组
        /// </summary>
        /// <param name="sourceByte">需要被解压缩的字节数组</param>
        /// <returns>解压后的字节数组</returns>
        private static byte[] deCompressBytes(byte[] sourceByte)
        {
            MemoryStream inputStream = new MemoryStream(sourceByte);
            Stream outputStream = deCompressStream(inputStream);
            byte[] outputBytes = new byte[outputStream.Length];
            outputStream.Position = 0;
            outputStream.Read(outputBytes, 0, outputBytes.Length);
            outputStream.Close();
            inputStream.Close();
            return outputBytes;
        }
        /// <summary>
        /// 压缩流
        /// </summary>
        /// <param name="sourceStream">需要被压缩的流</param>
        /// <returns>压缩后的流</returns>
        private static Stream compressStream(Stream sourceStream)
        {
            MemoryStream streamOut = new MemoryStream();
            ZOutputStream streamZOut = new ZOutputStream(streamOut, zlibConst.Z_DEFAULT_COMPRESSION);
            CopyStream(sourceStream, streamZOut);
            streamZOut.finish();
            return streamOut;
        }
        /// <summary>
        /// 解压缩流
        /// </summary>
        /// <param name="sourceStream">需要被解压缩的流</param>
        /// <returns>解压后的流</returns>
        private static Stream deCompressStream(Stream sourceStream)
        {
            sourceStream.Position = 0;
            MemoryStream outStream = new MemoryStream();
            ZOutputStream outZStream = new ZOutputStream(outStream);
            //sourceStream.CopyTo(outZStream);
            


            CopyStream(sourceStream, outZStream);
            outZStream.finish();
            return outStream;
        }


        public static IPSearch loadIpData()
        {

            try
            {
                MemoryStream ipFileMemory = new MemoryStream(File.ReadAllBytes("qqwry.dat"));
                ipFileMemory.Position = 0;
                return new IPSearch(ipFileMemory);
            }
            catch
            {
                try
                {
                    File.Delete("qqwry.dat");
                }
                catch
                {
                    
                }
                return null;

            }



        }

        public static IPSearch checkUpdate()
        {
            if (File.Exists("qqwry.dat") && (DateTime.Now- File.GetLastWriteTime("qqwry.dat")).TotalDays<=5)
            {
                return loadIpData();
            }
            else
            {
                getIpDataFromWeb();
                if (File.Exists("qqwry.dat"))
                {
                    return loadIpData();
                }
                else
                    return null;
            }
        }

    }
}
