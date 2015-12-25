/*
 * glacier_util.java
 */

import java.io.*;
import java.nio.file.*;

class inventory {
    private final Path pathname;
    private BufferedReader f;

    public inventory(String _pathname)
    {
        pathname = Paths.get(_pathname);
    }
    
    public String getPath()
    {
        return pathname.toString();
    }

    public void open() throws IOException
    {
        InputStream is = Files.newInputStream(pathname);
        f = new BufferedReader(new InputStreamReader(is));
    }

    public boolean parse()
    {
        if (f == null)
            return false;
    
        System.out.format("%s\n", pathname.toString());
        return true;
    }
}

public final class glacier_util {
    public static void main(String[] args)
    {
        String file;

        if (args.length == 0) {
            System.err.format("Must specify file\n");
            System.exit(1);
        }
        file = args[0];

        inventory i = new inventory(file);
        try {
            i.open();
        } catch (IOException e) {
            System.err.format("Couldn't open inventory %s", i.getPath());
            System.exit(1);
        }
        if (i.parse() == false)
            System.exit(1);

        System.exit(0);
    }
}

/* vi: set expandtab sw=4 ts=4: */
