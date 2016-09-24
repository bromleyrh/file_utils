/*
 * GlacierUtil.java
 */

import java.io.*;
import java.nio.file.*;
import java.util.Arrays;


final class Parser {
    private int indent;
    
    public Parser() {
        this.reset();
    }

    public String parse(String s) {
        int i, j;
        StringBuilder strb = new StringBuilder();

        for (i = 0; i < s.length(); i++) {
            char c = s.charAt(i);

            switch (c) {
            case '{':
            case '[':
                ++indent;
                strb.append(Character.toString(c));
                strb.append("\n");
                for (j = 0; j < indent; j++)
                    strb.append("\t");
                break;
            case '}':
            case ']':
                --indent;
                strb.append("\n");
                for (j = 0; j < indent; j++)
                    strb.append("\t");
                strb.append(Character.toString(c));
                break;
            case ',':
                strb.append(",\n");
                for (j = 0; j < indent; j++)
                    strb.append("\t");
                break;
            default:
                strb.append(Character.toString(c));
            }
        }

        return strb.toString();
    }
    
    public void reset() {
        indent = 0;
    }
}


final class InventoryFile {
    private final String pathname;
    private final BufferedReader f;

    public InventoryFile(String _pathname) throws IOException {
        InputStream is;

        pathname = _pathname;
        is = Files.newInputStream(Paths.get(pathname));
        f = new BufferedReader(new InputStreamReader(is));
    }
    
    public String getPath() {
        return pathname;
    }

    public void parse() throws IOException {
        char[] buf = new char[4096];
        Parser p = new Parser();

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


interface GlacierUtilCmdIface {
    abstract public boolean parseCmdline();
    abstract public int runCmd();
}


abstract class GlacierUtilCmd implements GlacierUtilCmdIface {
    boolean parsedCmdline = false;
    String[] args;
    String cmdname;
    
    public GlacierUtilCmd(String[] _args) {
        cmdname = this.getClass().getSimpleName();
        args = _args;
    }

    boolean doParseCmdline() {
        return true;
    }
    
    @Override public final boolean parseCmdline() {
        boolean ret = doParseCmdline();
        parsedCmdline = true;

        return ret;
    }
    
    int doRunCmd() {
        return 0;
    }
    
    @Override public final int runCmd() {
        return parsedCmdline ? doRunCmd() : -1;
    }
}


abstract class GlacierUtilSupercmd extends GlacierUtilCmd {
    GlacierUtilCmd subcmd;
    String[] subcmdargs;
    String subcmdstr;

    public GlacierUtilSupercmd(String[] _args) {
        super(_args);
    }

    private boolean getSubcmd() {
        if ((args == null) || (args.length == 0)) {
            System.err.print("\"" + cmdname + "\" command requires subcommand "
                             + "argument\n");
            return false;
        }

        subcmdstr = args[0];
        if (args.length > 1)
            subcmdargs = Arrays.copyOfRange(args, 1, args.length);

        return true;
    }

    boolean finishParseCmdline() {
        return true;
    }
  
    @Override public final boolean doParseCmdline() {
        return (getSubcmd() && finishParseCmdline());
    }
}


final class Format extends GlacierUtilCmd {
    private String file;

    public Format(String[] _args) {
        super(_args);
    }

    @Override public boolean doParseCmdline() {
        if ((args == null) || (args.length == 0)) {
            System.err.print("Must specify file\n");
            return false;
        }

        file = args[0];
        return true;
    }

    @Override public int doRunCmd() {
        InventoryFile i;

        try {
            i = new InventoryFile(file);
            i.parse();
        } catch (IOException e) {
            return -1;
        }

        return 0;
    }
}


final class Inventory extends GlacierUtilSupercmd {
    private char mode;

    public Inventory(String[] _args) {
        super(_args);
    }

    @Override boolean finishParseCmdline() {
        if (!subcmdstr.equals("format")) {
            System.err.print("Invalid subcommand \"" + subcmdstr + "\"\n");
            return false;
        }
        return true;
    }

    @Override public int doRunCmd() {
        Format fc = new Format(subcmdargs);

        if (fc.parseCmdline() == false)
            return -1;
        return fc.runCmd();
    }
}


public final class GlacierUtil extends GlacierUtilSupercmd {
    public GlacierUtil(String[] _args) {
        super(_args);
    }

    @Override public boolean finishParseCmdline() {
        if (!subcmdstr.equals("inventory")) {
            System.err.format("Invalid subcommand \"" + subcmdstr + "\"\n");
            return false;
        }
        return true;
    }
    
    @Override public int doRunCmd() {
        Inventory ic = new Inventory(subcmdargs);
        
        if (ic.parseCmdline() == false)
            return -1;
        return ic.runCmd();
    }

    public static void main(String[] args) {
        GlacierUtil gu = new GlacierUtil(args);
        
        if (gu.parseCmdline() == false)
            System.exit(1);
        if (gu.runCmd() != 0)
            System.exit(1);
        System.exit(0);
    }
}

/* vi: set expandtab sw=4 ts=4: */
