/*
 * manifest_util.java
 */

import java.io.*;
import javax.xml.parsers.*;
import org.xml.sax.*;
import org.xml.sax.helpers.*;

final class content_handler extends DefaultHandler {
    @Override public void startDocument() throws SAXException
    {
    }
    
    @Override public void endDocument() throws SAXException
    {   
    }
    
    @Override public void startElement(String namespace_uri, String local_name,
                                       String qname, Attributes attrs)
        throws SAXException
    {
    }
}

final class format_spec {
}

public final class manifest_util {
    private static String get_file_url(String _pathname)
    {
        String pathname = new File(_pathname).getAbsolutePath();
        
        if (File.separatorChar != '/')
            pathname = pathname.replace(File.separatorChar, '/');
        if (!pathname.startsWith("/"))
            pathname = "/" + pathname;
        
        return "file:" + pathname;
    }

    public static void main(String[] args)
    {
        String fileurl;

        if (args.length == 0) {
            System.err.print("Must specify file\n");
            System.exit(1);
        }
        fileurl = get_file_url(args[0]);

        System.exit(0);
    }
}

/* vi: set expandtab sw=4 ts=4: */