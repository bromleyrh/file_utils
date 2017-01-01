/*
 * verify-gui.c
 */

#include <gtk/gtk.h>

#include <stdlib.h>

static void test(GtkWidget *, gpointer);
static gboolean delete_ev(GtkWidget *, GdkEvent *, gpointer);
static void destroy(GtkWidget *, gpointer);

static void
test(GtkWidget *widget, gpointer data)
{
    g_print("Test %s\n", data);
}

static gboolean
delete_ev(GtkWidget *widget, GdkEvent *ev, gpointer data)
{
    g_print("Delete\n");
    return TRUE;
}

static void
destroy(GtkWidget *widget, gpointer data)
{
    gtk_main_quit();
}

int
main(int argc, char **argv)
{
    GtkWidget *box;
    GtkWidget *button;
    GtkWidget *window;

    gtk_init(&argc, &argv);

    window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

    gtk_container_set_border_width(GTK_CONTAINER(window), 10);

    g_signal_connect(window, "delete-event", G_CALLBACK(delete_ev), NULL);
    g_signal_connect(window, "destroy", G_CALLBACK(destroy), NULL);

    box = gtk_hbox_new(FALSE, 0);
    gtk_container_add(GTK_CONTAINER(window), box);

    button = gtk_button_new_with_label("Test 1");

    g_signal_connect(button, "clicked", G_CALLBACK(test), (gpointer)"1");

    gtk_box_pack_start(GTK_BOX(box), button, TRUE, TRUE, 0);

    gtk_widget_show(button);

    button = gtk_button_new_with_label("Test 2");

    g_signal_connect(button, "clicked", G_CALLBACK(test), (gpointer)"2");

    gtk_box_pack_start(GTK_BOX(box), button, TRUE, TRUE, 0);

    gtk_widget_show(button);

    gtk_widget_show(box);

    gtk_widget_show(window);

    gtk_main();

    return EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
