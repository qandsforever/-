using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PacketDotNet
{
    public enum DnsQueryClass
    {
        IN = 0x01, //指定 Internet 类别。 
        CSNET = 0x02, //指定 CSNET 类别。（已过时） 
        CHAOS = 0x03, //指定 Chaos 类别。 
        HESIOD = 0x04,//指定 MIT Athena Hesiod 类别。 
        ANY = 0xFF //指定任何以前列出的通配符。 
    };

    public enum DnsQueryType
    {
        A = 0x01, //指定计算机 IP 地址。 
        NS = 0x02, //指定用于命名区域的 DNS 名称服务器。 
        MD = 0x03, //指定邮件接收站（此类型已经过时了，使用MX代替） 
        MF = 0x04, //指定邮件中转站（此类型已经过时了，使用MX代替） 
        CNAME = 0x05, //指定用于别名的规范名称。 
        SOA = 0x06, //指定用于 DNS 区域的“起始授权机构”。 
        MB = 0x07, //指定邮箱域名。 
        MG = 0x08, //指定邮件组成员。 
        MR = 0x09, //指定邮件重命名域名。 
        NULL = 0x0A, //指定空的资源记录 
        WKS = 0x0B, //描述已知服务。 
        PTR = 0x0C, //如果查询是 IP 地址，则指定计算机名；否则指定指向其它信息的指针。 
        HINFO = 0x0D, //指定计算机 CPU 以及操作系统类型。 
        MINFO = 0x0E, //指定邮箱或邮件列表信息。 
        MX = 0x0F, //指定邮件交换器。 
        TXT = 0x10, //指定文本信息。 
        UINFO = 0x64, //指定用户信息。 
        UID = 0x65, //指定用户标识符。 
        GID = 0x66, //指定组名的组标识符。 
        ANY = 0xFF //指定所有数据类型。 

    }
    public class DnsPacket
    {
        public DnsPacket()
        {
            Questions = new List<DnsQuestion>();
            Records = new List<DnsRecord>();
        }
        public List<DnsQuestion> Questions{ get; }
        public List<DnsRecord> Records { get; }

         int requestCount = 0;
         int responseCount = 0;
        public bool Parse(byte[] data)
        {
            if (data.Length < 12) return false; //头12自己
            if (data[2] != 0x81 || data[3] != 0x80) return false; //标志位，不正确则丢

            requestCount = data[4] * 256 + data[5];
            responseCount = data[6] * 256 + data[7];
            int offset = 12;
       

            for (int i = 0; i < requestCount; i++)
            {
                // var ZeroByteOffset = Enumerable.Range(0, data.Length).Where(x => data[x] == 0).First();
;
                string name = getQueryName(data, offset, out offset);
                if (name == null) return false;
                offset++;
                DnsQueryType dnsType = (DnsQueryType)data[offset + 1];
                DnsQueryClass dnsClass = (DnsQueryClass)data[offset + 3];

                Questions.Add(new DnsQuestion() { name = name, dnsClass = dnsClass, dnsType = dnsType });
                offset = offset + 4;

            }

            for (int i = 0; i < responseCount; i++)
            {
                DnsRecord record = new DnsRecord();
                int labeLen;
                record.Name = GetLabelName(data, offset, out labeLen);
                offset += labeLen;
                offset++;
                record.QType = (DnsQueryType)data[++offset];
                //
                offset++;
                record.QClass = (DnsQueryClass)data[++offset];
                //
                offset++;
                record.TTL = data[offset++] * 256 * 256 * 256 + data[offset++] * 256 * 256 + data[offset++] * 256 + data[offset++];
                //
                record.RDLength = data[offset++] * 256 + data[offset++];


                switch (record.QType)
                {
                    case DnsQueryType.A:
                        record.RDDate = new A_RR(data, offset, record.RDLength);
                        break;
                    case DnsQueryType.CNAME:
                        record.RDDate = new CNAME_RR(data, offset, record.RDLength);
                        break;
                    case DnsQueryType.MX:
                        record.RDDate = new MX_RR(data, offset, record.RDLength);
                        break;
                    case DnsQueryType.NS:
                        record.RDDate = new NS_RR(data, offset, record.RDLength);
                        break;
                    case DnsQueryType.SOA:
                        record.RDDate = new SOA_RR(data, offset, record.RDLength);
                        break;
                    case DnsQueryType.TXT:
                        record.RDDate = new TXT_RR(data, offset, record.RDLength);
                        break;
                }
                Records.Add(record);
                offset += record.RDLength;


            }

            return true;
        }

        string getRecorStr(byte[] data)
        {
            return null;
        }


        public static string GetLabelName(byte[] data, int offset, out int labelLen)
        {
            bool alreadyJump = false;
            int seek = offset;
            int len = data[seek];
            labelLen = 0;
            StringBuilder result = new StringBuilder(63);
            while (len > 0 && seek < data.Length)
            {
                if (len > 191 && len < 255)
                {
                    if (alreadyJump)
                    {
                        labelLen = seek - offset;
                        return result.ToString();
                    }
                    int tempLen;
                    result.Append(GetLabelName(data, data[++seek] + (len - 192) * 256, out tempLen));
                    alreadyJump = true;
                    labelLen = seek - offset;
                    return result.ToString();
                }
                else if (len < 64)
                {
                    for (; len > 0; len--)
                    {
                        result.Append((char)data[++seek]);
                    }
                    len = data[++seek];
                    if (len > 0) result.Append(".");
                }
            }
            labelLen = seek - offset;
            return result.ToString();
        }

        string getQueryName(byte[] data ,int offset,out int currentOffset)
        {


            try
            {
                List<string> name = new List<string>();
                while (offset < data.Length)
                {
                    if (data[offset] > 0)
                    {
                        name.Add(System.Text.Encoding.Default.GetString(data.Skip(offset+1).Take(data[offset]).ToArray()));
                        offset = offset + data[offset] + 1;
                   
                        //data = data.Skip(data[offset] + 1).ToArray();
                       
                    }
                    else
                    {
                 
                        break;
                    }
                }
                if (name.Count == 0)
                {
                    currentOffset = offset;
                    return null;
                }
                else
                {
                    currentOffset = offset;
                    return string.Join(".", name);
                }
            }
            catch
            {
                currentOffset = offset;
                return null;
            }

          

        }


    }

    public class DnsQuestion
    {
        public string name { get; set; }
        public DnsQueryType dnsType { get; set; }
        public DnsQueryClass dnsClass { get; set; }

    }

    public class DnsRecord
    {
        // NAME 资源记录包含的域名
        //TYPE    2个字节表示资源记录的类型，指出RDATA数据的含义
        //CLASS   2个字节表示RDATA的类
        //TTL     4字节无符号整数表示资源记录可以缓存的时间。0代表只能被传输，但是不能被缓存。
        //RDLENGTH        2个字节无符号整数表示RDATA的长度
        //RDATA   不定长字符串来表示记录，格式根TYPE和CLASS有关。比如，TYPE是A，CLASS 是 IN，那么RDATA就是一个4个字节的ARPA网络地址。
      
        public string Name
        {
            get;
            set;
        }
        //byte[] _name;
        public DnsQueryType QType
        {
            get;
            set;
        }
        public DnsQueryClass QClass
        {
            get;
            set;
        }
        public int TTL
        {
            get;
            set;
        }
        public int RDLength
        {
            get;
            set;
        }
        public object RDDate
        {
            get;
            set;

        }
    }


    public class A_RR
    {
        public string address { get; set; }
        public override string ToString()
        {
            return address;
        }
        public A_RR(byte[] data, int offset, int len)
        {
            for (int i = 0; i < 4; i++)
            {
                address += data[offset++].ToString() + ".";
            }
            address = address.TrimEnd('.');
        }
    }
    public class CNAME_RR
    {
        public string name { get; set; }
        public override string ToString()
        {
            return name;
        }
        public CNAME_RR(byte[] data, int offset, int len)
        {
            int labelLen;
            name += DnsPacket.GetLabelName(data, offset, out labelLen);

        }
    }
    public class MX_RR
    {
        public int Preference { get; set; }
        public string Mail { get; set; }
        public override string ToString()
        {
            return string.Format("Preference={0} | Mail={1}", Preference, Mail);
        }
        public MX_RR(byte[] data, int offset, int len)
        {
            Preference = data[offset++] * 256 + data[offset++];
            int labelLen;
            Mail = DnsPacket.GetLabelName(data, offset, out labelLen);

        }
    }
    public class NS_RR
    {
        public string NameServer { get; set; }
        public override string ToString()
        {
            return NameServer;
        }
        public NS_RR(byte[] data, int offset, int len)
        {
            int labelLen;
            NameServer += DnsPacket.GetLabelName(data, offset, out labelLen);

        }
    }
    public class SOA_RR
    {
        public string NameServer { get; set; }
        public string Mail { get; set; }
        public int Serial { get; set; }
        public int Refresh { get; set; }
        public int Retry { get; set; }
        public int Expire { get; set; }
        public int TTL { get; set; }
        public override string ToString()
        {
            return string.Format("nameServer={0} | mail={1} | serial={2} | refresh={3} | ...", NameServer, Mail, Serial, Refresh);
        }
        public SOA_RR(byte[] data, int offset, int len)
        {
            int endOffset = offset + len;
            int labelLen;
            NameServer = DnsPacket.GetLabelName(data, offset, out labelLen);
            offset += labelLen;
            Mail = DnsPacket.GetLabelName(data, ++offset, out labelLen);
            offset += labelLen;
            offset++;
            Serial = data[offset++] * 256 * 256 * 256 + data[offset++] * 256 * 256 + data[offset++] * 256 + data[offset++];
            Refresh = data[offset++] * 256 * 256 * 256 + data[offset++] * 256 * 256 + data[offset++] * 256 + data[offset++];
            Retry = data[offset++] * 256 * 256 * 256 + data[offset++] * 256 * 256 + data[offset++] * 256 + data[offset++];
            Expire = data[offset++] * 256 * 256 * 256 + data[offset++] * 256 * 256 + data[offset++] * 256 + data[offset++];
            TTL = data[offset++] * 256 * 256 * 256 + data[offset++] * 256 * 256 + data[offset++] * 256 + data[offset++];
        }
    }

    public class TXT_RR
    {
        public string text { get; set; }
        public override string ToString()
        {
            return text;
        }
        public TXT_RR(byte[] data, int offset, int len)
        {
            //由于txt的字段有可能大于63，超出一般GetLabelName的字符串长度。
            StringBuilder build = new StringBuilder(len);
            for (; len > 0; len--)
            {
                build.Append((char)data[offset++]);
            }
            text = build.ToString();
        }
    }

}
