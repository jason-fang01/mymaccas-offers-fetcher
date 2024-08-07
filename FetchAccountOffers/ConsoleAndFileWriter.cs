namespace MyMaccasOffersFetcher
{
    using System.Text;

    public class ConsoleAndFileWriter : TextWriter
    {
        private TextWriter console;

        private StreamWriter file;

        public ConsoleAndFileWriter(string path)
        {
            console = Console.Out;
            file = new StreamWriter(path, true);
        }

        public override void Write(char value)
        {
            console.Write(value);
            file.Write(value);
        }

        public override void WriteLine(string value)
        {
            console.WriteLine(value);
            file.WriteLine(value);
        }

        public override Encoding Encoding => Encoding.UTF8;

        public override void Flush()
        {
            console.Flush();
            file.Flush();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                console.Dispose();
                file.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
