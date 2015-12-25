/*
 * glacier_util.java
 */

import java.io.*;
import java.nio.file.*;

final class parser {
    private int indent;
    
    public parser()
    {
        this.reset();
    }

    public String parse(String s)
    {
        int i, j;
        StringBuilder ret = new StringBuilder();

        for (i = 0; i < s.length(); i++) {
            char c = s.charAt(i);

            switch (c) {
            case '{':
            case '[':
                ++indent;
                ret.append(Character.toString(c));
                ret.append("\n");
                for (j = 0; j < indent; j++)
                    ret.append("\t");
                break;
            case '}':
            case ']':
                --indent;
                ret.append("\n");
                for (j = 0; j < indent; j++)
                    ret.append("\t");
                ret.append(Character.toString(c));
                break;
            case ',':
                ret.append(",\n");
                for (j = 0; j < indent; j++)
                    ret.append("\t");
                break;
            default:
                ret.append(Character.toString(c));
            }
        }

        return ret.toString();
    }
    
    public void reset()
    {
        indent = 0;
    }
}

final class inventory {
    private final String pathname;
    private final BufferedReader f;

    public inventory(String _pathname) throws IOException
    {
        InputStream is;

        pathname = _pathname;
        is = Files.newInputStream(Paths.get(pathname));
        f = new BufferedReader(new InputStreamReader(is));
    }
    
    public String getPath()
    {
        return pathname;
    }

    public void parse() throws IOException
    {
        char[] buf = new char[1024 * 1024];
        parser p = new parser();

        for (;;) {
            boolean end = false;
            int off, numread;

            for (off = 0; off < buf.length; off += numread) {
                numread = f.read(buf, off, buf.length - off);
                if (numread == -1) {
                    end = true;
                    break;
                }
            }

            System.out.print(p.parse(new String(buf, 0, off)));
            if (end)
                break;
        }

        System.out.print("\n");
    }
}

public final class glacier_util {
    public static void main(String[] args)
    {
        inventory i;
        String file;

        if (args.length == 0) {
            System.err.print("Must specify file\n");
            System.exit(1);
        }
        file = args[0];

        try {
            i = new inventory(file);
            i.parse();
        } catch (IOException e) {
            System.err.format("Couldn't parse inventory %s", file);
            System.exit(1);
        }

        System.exit(0);
    }
}

/* vi: set expandtab sw=4 ts=4: */
