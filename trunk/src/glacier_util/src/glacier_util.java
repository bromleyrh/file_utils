/*
 * glacier_util.java
 */

import java.io.*;
import java.nio.file.*;
import java.util.Arrays;

final class parser {
    private int indent;
    
    public parser()
    {
        this.reset();
    }

    public String parse(String s)
    {
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
    
    public void reset()
    {
        indent = 0;
    }
}

final class inventory_file {
    private final String pathname;
    private final BufferedReader f;

    public inventory_file(String _pathname) throws IOException
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
        char[] buf = new char[4096];
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

interface glacier_util_cmd_iface {
    abstract public boolean parse_cmdline();
    abstract public int run_cmd();
}

abstract class glacier_util_cmd implements glacier_util_cmd_iface {
    boolean parsed_cmdline = false;
    String[] args;
    String cmdname;
    
    public glacier_util_cmd(String[] _args)
    {
        cmdname = this.getClass().getSimpleName();
        args = _args;
    }

    boolean do_parse_cmdline()
    {
        return true;
    }
    
    final @Override public boolean parse_cmdline()
    {
        boolean ret = do_parse_cmdline();
        parsed_cmdline = true;

        return ret;
    }
    
    int do_run_cmd()
    {
        return 0;
    }
    
    final @Override public int run_cmd()
    {
        if (!parsed_cmdline)
            return -1;

        return do_run_cmd();
    }
}

abstract class glacier_util_supercmd extends glacier_util_cmd {
    glacier_util_cmd subcmd;
    String[] subcmdargs;
    String subcmdstr;

    public glacier_util_supercmd(String[] _args)
    {
        super(_args);
    }

    private boolean get_subcmd()
    {
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

    boolean finish_parse_cmdline()
    {
        return true;
    }
  
    final @Override public boolean do_parse_cmdline()
    {
        return (get_subcmd() && finish_parse_cmdline());
    }
}

final class parse extends glacier_util_cmd {
    private String file;

    public parse(String[] _args)
    {
        super(_args);
    }

    @Override public boolean do_parse_cmdline()
    {
        if ((args == null) || (args.length == 0)) {
            System.err.print("Must specify file\n");
            return false;
        }

        file = args[0];
        return true;
    }

    @Override public int do_run_cmd()
    {
        inventory_file i;

        try {
            i = new inventory_file(file);
            i.parse();
        } catch (IOException e) {
            return -1;
        }

        return 0;
    }
}

final class format extends glacier_util_cmd {
    private String file;
    
    public format(String[] _args)
    {
        super(_args);
    }
    
    @Override public boolean do_parse_cmdline()
    {
        if ((args == null) || (args.length == 0)) {
            System.err.print("Must specify file");
            return false;
        }
        
        file = args[0];
        return true;
    }
    
    @Override public int do_run_cmd()
    {
        System.err.print("Not yet implemented");
        return -1;
    }
}

final class inventory extends glacier_util_supercmd {
    private char mode;

    public inventory(String[] _args)
    {
        super(_args);
    }

    @Override boolean finish_parse_cmdline()
    {
        if (subcmdstr.equals("parse"))
            mode = 'p';
        else if (subcmdstr.equals("format"))
            mode = 'f';
        else {
            System.err.print("Invalid subcommand \"" + subcmdstr + "\"\n");
            return false;
        }
        return true;
    }

    @Override public int do_run_cmd()
    {
        int ret;

        switch (mode) {
        case 'p':
            {
                parse pc = new parse(subcmdargs);

                if (pc.parse_cmdline() == false)
                    ret = -1;
                else
                    ret = pc.run_cmd();
                break;
            }
        case 'f':
            {
                format fc = new format(subcmdargs);

                if (fc.parse_cmdline() == false)
                    ret = -1;
                else
                    ret = fc.run_cmd();
                break;
            }
        default:
            ret = -1;
        }
        
        return -1;
    }
}

public final class glacier_util extends glacier_util_supercmd {
    public glacier_util(String[] _args)
    {
        super(_args);
    }

    @Override public boolean finish_parse_cmdline()
    {
        if (!subcmdstr.equals("inventory")) {
            System.err.format("Invalid subcommand \"" + subcmdstr + "\"\n");
            return false;
        }
        return true;
    }
    
    @Override public int do_run_cmd()
    {
        inventory ic = new inventory(subcmdargs);
        
        if (ic.parse_cmdline() == false)
            return -1;
        return ic.run_cmd();
    }

    public static void main(String[] args)
    {
        glacier_util gu = new glacier_util(args);
        
        if (gu.parse_cmdline() == false)
            return;
        gu.run_cmd();
    }
}

/* vi: set expandtab sw=4 ts=4: */
