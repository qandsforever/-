using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace 网络抓包分析
{
    public partial class Form3 : Form
    {
        public Form3()
        {
            InitializeComponent();
        }

        private void Form3_Resize(object sender, EventArgs e)
        {
            textBox1.Size = new Size(this.Width - 10, this.Height - 10);
            textBox1.Location = new Point(0, 0);
        }
    }
}
