#define _GNU_SOURCE // setresuid, setresgid

// cannot use pwd.h if you plan on compiling with static linking
// #include <pwd.h> // getpwuid, getpwnam
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h> // vfprintf
#include <unistd.h> // getpass, getuid & setuid, fork
#include <sys/wait.h> // waitpid

// comment this out to only set effective uid of target program
#define SET_REAL_UID

// Just fprintf to stderr and then exit with error code
void
print_error_and_exit(const char *format, ...)
{
	// First we'll remove the target user saved uid and gid
	uid_t my_uid = getuid();
	gid_t my_gid = getgid();
	setresuid(my_uid, my_uid, my_uid);
	setresgid(my_gid, my_gid, my_gid);

	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	exit(1);
}

// re-definitions of pwd.h struct and functions
// don't use these if we've included pwd.h

#ifndef _PWD_H

struct passwd {
	// 33 bytes allows 32-byte username and null-terminator
	char  pw_name[33];
	uid_t pw_uid;
	gid_t pw_gid;
};

/*
 * Input:
 * If searching by uid, empty string and desired uid
 * If seraching by username, username and -1 for uid
 *
 * Output:
 * Barebones passwd struct analog of pwd.h passwd
 *
 * Calling of this function should only be performed by
 * getpwuid and getpwnam helper functions below
 */
struct passwd *
getpw(const char *username, const uid_t uid)
{
	FILE *fp = fopen("/etc/passwd", "r");
	if (fp == NULL) // This should probably never happen
		print_error_and_exit("Could not open /etc/passwd\n");
	struct passwd *result = NULL;
	char buf[1024];

	// Read /etc/passwd line-by-line
	for (int line = 1; fgets(buf, 1024, fp) != NULL; line++) {
		// First, read in username
		char *start, *end;
		start = buf;
		end = strchr(buf, ':');
		if (end == NULL)
			print_error_and_exit("/etc/passwd parse error at line %d\n", line);
		*end = '\0';
		char *entry_uname = start;

		// If we're retrieving by username (uid == -1)
		// we should continue the loop only if the username doesn't match
		// otherwise we'll keep going until we can check uid
		if (uid == -1 && strcmp(username, entry_uname) != 0)
			continue;

		// Now read in the uid, ignoring the password entry
		// which should always be just "x", by skipping ahead 3 bytes
		start = end + 3;
		end = strchr(start, ':');
		if (end == NULL)
			print_error_and_exit("/etc/passwd parse error at line %d\n", line);
		*end = '\0';

		// We convert the string to a uid_t
		char *uid_str = start;
		char *tol_end = uid_str;
		uid_t entry_uid = strtol(uid_str, &tol_end, 10);

		// If it's the uid we want, or we already have the username we want
		// we can get the gid and return a struct
		// otherwise, we keep searching
		if (uid != entry_uid && uid != -1)
			continue;

		// get the gid
		start = end + 1;
		end = strchr(start, ':');
		if (start == NULL)
			print_error_and_exit("/etc/passwd parse error at line %d\n", line);
		*end = '\0';
		char *gid_str = start;

		// convert to a gid_t
		tol_end = gid_str;
		gid_t entry_gid = strtol(gid_str, &end, 10);

		// create the passwd struct and return it
		// this will need to be freed later
		result = (struct passwd *)malloc(sizeof(struct passwd));
		strcpy(result->pw_name, entry_uname);
		result->pw_uid = entry_uid;
		result->pw_gid = entry_gid;

		break;
	}

	fclose(fp);
	// Will return NULL if we didn't find what we were looking for
	return result;
}

// Helper functions for getpw
// these are direct replacements for the ones in pwd.h
struct passwd *
getpwuid(const uid_t uid)
{
	return getpw("", uid);
}

struct passwd *
getpwnam(const char *username)
{
	return getpw(username, -1);
}

#endif

/* 
 * checks whether the current user is authorized
 * to run programs as the target user given the
 * password as specified in /etc/runas
 *
 * returns:
 * 0 if user authorized
 * 1 if not authorized
 * 2 if incorrect password
 */
int
check_user_authorization(const char *current_uname, const char *target_uname, const char *password, FILE *runas)
{
	// buffer should be more than enough
	// for two 32-byte usernames (the maximum)
	// plus a 255-byte password
	char buf[384];

	// Read in lines one at a time
	for (int line = 1; fgets(buf, 384, runas) != NULL; line++) {
		// read in username
		char *start, *end;
		start = buf;
		end = strchr(start, ':');
		if (end == NULL)
			print_error_and_exit("/etc/runas parse error at line %d\n", line);
		*end = '\0';
		char *entry_uname = start;

		// compare username to one in current entry
		// if it's not our current username, keep searching
		if (strcmp(entry_uname, current_uname) != 0)
			continue;

		// username matches
		// get the target username
		start = end + 1;
		end = strchr(start, ':');
		if (end == NULL)
			print_error_and_exit("/etc/runas parse error at line %d\n", line);
		*end = '\0';
		char *entry_target = start;

		// compare target username to one in current entry
		// if it's not the one we're looking for, keep searching
		if (strcmp(entry_target, target_uname) != 0)
			continue;

		// target username matches
		// get the password
		start = end + 1;
		end = strchr(start, '\n');
		if (end == NULL)
			print_error_and_exit("/etc/runas parse error at line %d\n", line);
		*end = '\0';
		char *entry_pw = start;

		// compare password to one in current entry
		// return 0 if the password matches, otherwise return 2
		return strcmp(entry_pw, password) == 0 ? 0 : 2;
	}

	return 1;
}

int
main(int argc, char *argv[])
{
	// Print help text
	if (argc < 3 || !strcmp(argv[1], "-h")) {
		// Minimum arguments not passed
		setresuid(-1, getuid(), getuid());
		printf("Usage:\n");
		printf("%s <username> <program> [arg1 arg2 arg3 ...]\n\n", argv[0]);
		printf("Options:\n");
		printf("username: the username that you want to run the specified program as\n");
		printf("program: the program that you want to run, followed by the arguments to the program\n");
		printf("-h: show this text\n");
		exit(1);
	}

	// Open /etc/runas immediately, but leave it open so we can drop priveleges
	// This works because of the way Linux handles file streams
	// Once a stream is open, it doesn't check the permissions!
	// We still want to close the stream as quickly as possible though
	FILE *runas = fopen("/etc/runas", "r");
	if (runas == NULL)
		print_error_and_exit("Could not open /etc/runas\n");

	// Do the same for /var/tmp/runaslog
	// If we can't open it, we don't worry about it until the end
	FILE *log = fopen("/var/tmp/runaslog", "a");        

	// Here we get the target user info
	const struct passwd *target_user = getpwnam(argv[1]);
	if (target_user == NULL) // this could happen realistically
		print_error_and_exit("Target user %s not found in /etc/passwd\n", argv[1]);

	/******************
	* Drop priveleges *
	******************/
	// Now we can already completely drop root priveleges
	// but first we place the target uid into the saved uid
	// so we can use their priveleges later
	setresuid(-1, getuid(), target_user->pw_uid);
	setresgid(-1, getgid(), target_user->pw_gid);

	// We put as little code as possible before this privelege drop

	// Here we get the current (real) user info
	const struct passwd *current_user = getpwuid(getuid());
	if (current_user == NULL) // this should probably never happen
		print_error_and_exit("Current user with uid %lu not found in /etc/passwd\n", (unsigned long int) current_user->pw_uid);

	// Retrieve password from stdin
	const char *password = getpass("Password: ");

	/*************************
	* Check user credentials *
	*************************/
	// This is as early as we can possibly check credentials
	int auth = check_user_authorization(current_user->pw_name, target_user->pw_name, password, runas);
	// Now we can close the /etc/runas stream
	// but /var/tmp/runaslog is still open!
	fclose(runas);

	// if not authorized, exit with error code
	// otherwise we will continue to execution
	if (auth == 2)
		print_error_and_exit("Incorrect password entered\n");
	if (auth == 1)
		print_error_and_exit("User %s not authorized to run programs as %s\n", current_user->pw_name, target_user->pw_name);
	
	/********************
	*  Execute program  *
	********************/
	// Arguments to pass to execvp (includes program)
	// argv is already null-terminated
	// we could just pass in argv[2] and &argv[2] to execvp
	// but this is a little bit more clear, I think
	char * const *exec_args = &argv[2];

	// From "Advanced Programming" ch. 1
	int status;
	pid_t pid;
	errno = 0;
	// Fork off new process
	if ((pid = fork()) < 0)
		print_error_and_exit("Unable to fork new process\n%s\n", strerror(errno));
	if (pid == 0) {
		// Child process
		// Now we set the effective uid & gid to that of target user
		// This works because the target user uid is the saved uid
		seteuid(target_user->pw_uid);
		setegid(target_user->pw_gid);

		// Can only set real uid when unpriveleged by swapping with effective uid
		// Then we can just set the effective uid back to what it was before swapping
		// we shouldn't need to set real uid unless the executed program has
		// a call to access(2), which check real uid instead of effective uid
		#ifdef SET_REAL_UID
		setreuid(geteuid(), getuid());
		seteuid(getuid());
		setregid(getegid(), getgid());
		setegid(getgid());
		#endif

		// Print some info:

		// struct passwd *real_user = getpwuid(getuid());
		// struct passwd *eff_user = getpwuid(geteuid());       
		// printf("Real user / uid:\t %s / %lu\nEffective user / uid:\t %s / %lu\n",
		//      real_user->pw_name, (unsigned long int) real_user->pw_uid,
		//      eff_user->pw_name, (unsigned long int) eff_user->pw_uid);

		// execute program with arguments
		execvp(exec_args[0], exec_args);

		// If we get to here, the execution failed
		// Kill the process so it doesn't execute further
		print_error_and_exit("Unable to execute program %s\n%s\n", exec_args[0], strerror(errno));
	}

	// Now we can reset saved uid to our real uid
	setresuid(-1, -1, getuid());

	// Wait for child process or exit with error
	if ((pid = waitpid(pid, &status, 0)) < 0)
		print_error_and_exit("waitpid failure\n%s\n", strerror(errno));

	/******************
	*  Log execution  *
	******************/ 
	// append exit status to /var/tmp/runaslog if it is writable
	if (log != NULL) {
		fprintf(log, "%d", WIFEXITED(status) ? 0 : WEXITSTATUS(status));
		// append program name and arguments
		for (int i = 0; exec_args[i] != NULL; i++)
			fprintf(log, " %s", exec_args[i]);
		fprintf(log, "\n");
		fclose(log);
	} else {
		fprintf(stderr, "Could not open /var/tmp/runaslog\n");
		// Since we can't log to file, we'll output exit status to terminal
		if (WIFEXITED(status))
			printf("%s exited successfully\n", exec_args[0]);
		else
			printf("%s exited unsuccessfully with return code %d\n", exec_args[0], WEXITSTATUS(status));
	}

	exit(0);
}
