#define LOG_TAG "deadbinder"

#include <binder/Parcel.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>
#include <binder/TextOutput.h>
#include <binder/Binder.h>
#include <binder/BpBinder.h>

using namespace android;

unsigned long hash(const char *str)
{
    unsigned long hash = 5381;
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

char *next_word(char **input) {
    char *ret = *input;
    *input = strchr(*input, ' ') ?: *input + strlen(*input);
    **input = 0;
    (*input)++;
    return ret;
}

class MyBinder : public BBinder {
public:
    MyBinder(const char* name) {
        mName = strdup(name);

        printf("Created binder: %s\n", name);
    }

    ~MyBinder() {
        printf("Destroyed binder: %s\n", mName);
        free(mName);
    }

    const char *getName() const {
        return mName;
    }
private:
    char *mName;
};

KeyedVector<unsigned long, sp<MyBinder> > binders;
KeyedVector<unsigned long, sp<BpBinder> > proxies;

void list_binders(const char *type) {
    if (type && strcmp(type, "binder") == 0) {
        puts("Binders:");
        for (size_t i = 0; i < binders.size(); i++) {
            puts(binders[i]->getName());
        }
    } else if (type && strcmp(type, "proxy") == 0) {

    } else {
        printf("Unknown type '%s'. Allowed: 'binder', 'proxy'\n", type);
    }
}

void create_binder(const char *name) {
    sp<MyBinder> m(new MyBinder(name));
    binders.add(hash(name), m);
    printf("Added binder %s. List size: %d\n", m->getName(), (int)binders.size());
}

void publish_binder(const char *name) {
    String16 sName(name);
    defaultServiceManager()->addService(sName, binders.valueFor(hash(name)), false);
    printf("Published binder %s\n", name);
}

void fetch_binder(const char */*name*/) {

}

void release_binder(const char *type, const char *name) {
    if (type && strcmp(type, "binder") == 0) {
        sp<MyBinder> m = binders.valueFor(hash(name));
        binders.removeItem(hash(name));
        printf("Removed binder %s. List size: %d\n", m->getName(), (int)binders.size());
    } else if (type && strcmp(type, "proxy") == 0) {

    } else {
        printf("Unknown type '%s'. Allowed: 'binder', 'proxy'\n", type);
    }
}

void kill_binder(const char *name) {
    sp<MyBinder> m = binders.valueFor(hash(name));
    m->enableCollection();
    printf("Killed binder %s.\n", m->getName());
}

void perform_transaction(const char */*name*/, const char */*tx*/, const char */*parm*/) {

}

int main() {
    char buf[256];
    do {
        fgets(buf, 256, stdin);
        buf[strcspn(buf, "\r\n")] = 0;

        char *line = buf;

        char *command = next_word(&line);

        if (strcmp(command, "list") == 0) {
            list_binders(next_word(&line));
        } else if (strcmp(command, "create") == 0) {
            create_binder(next_word(&line));
        } else if (strcmp(command, "publish") == 0) {
            publish_binder(next_word(&line));
        } else if (strcmp(command, "fetch") == 0) {
            fetch_binder(next_word(&line));
        } else if (strcmp(command, "release") == 0) {
            char *type = next_word(&line);
            char *name = next_word(&line);
            release_binder(type, name);
        } else if (strcmp(command, "kill") == 0) {
            kill_binder(next_word(&line));
        } else if (strcmp(command, "trans") == 0) {
            char *name = next_word(&line);
            char *tx = next_word(&line);
            char *parm = next_word(&line);
            perform_transaction(name, tx, parm);
        } else if (strcmp(command, "exit") == 0) {
            return 0;
        } else {
            printf("Unknown command: '%s'\n", command);
        }
    } while (true);
}