#define _GNU_SOURCE // setresuid, setresgid

// cannot use pwd.h if you plan on using static linking
// #include <pwd.h> // getpwuid, getpwnam
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h> // getpass, getuid & setuid, fork
#include <sys/wait.h> // waitpid

// comment this out to only set effective uid of program
#define SET_REAL_UID

// re-definitions of pwd.h struct and functions
// don't use these if we've included pwd.h

#ifndef _PWD_H

struct passwd {
	char pw_name[33];
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
	if (fp == NULL) {
		fprintf(stderr, "Could not open /etc/passwd\n");
		exit(1);
	}

	char buf[1024];
	// Read /etc/passwd line-by-line
	for (int linenum = 1; fgets(buf, 1024, fp) != NULL; linenum++) {
		// First part of entry is username, which we store for now
		char *entry_uname = strtok(buf, ":");

		// If we're retrieving by username (uid == -1)
		// we should continue the loop if the username doesn't match
		// otherwise we'll keep going until we can check uid
		if (uid != -1 || !strcmp(username, entry_uname)){
			if (entry_uname == NULL) {
				fprintf(stderr, "/etc/passwd parse error\n");
				exit(1);
			}

			// We ignore the password part of the entry
			// which should always be just "x"
			strtok(NULL, ":");
			// Next is uid
			char *uid_str = strtok(NULL, ":");
			if (uid_str == NULL) {
				fprintf(stderr, "/etc/passwd parse error\n");
				exit(1);
			}
			char *end = uid_str;
			// We convert the string to a uid_t
			uid_t entry_uid = strtol(uid_str, &end, 10);

			// If it's the uid we want, or we already have the username we want
			// we get the gid and return a struct
			// otherwise, we keep searching
			if (uid == entry_uid || uid == -1) {
				// get the gid
				char *gid_str = strtok(NULL, ":");
				if (gid_str == NULL) {
					fprintf(stderr, "/etc/passwd parse error\n");
					exit(1);
				}
				end = gid_str;
				// convert to a gid_t
				gid_t entry_gid = strtol(gid_str, &end, 10);
	
				// create the passwd struct and return it
				struct passwd *result = (struct passwd *)malloc(sizeof(struct passwd));
				strcpy(result->pw_name, entry_uname);
				result->pw_uid = entry_uid;
				result->pw_gid = entry_gid;

				fclose(fp);
				return result;
			}
		}
	}

	fclose(fp);
	return NULL;
}

// Helper functions for getpw
// these are direct replacements for the ones in pwd.h
struct passwd *
getpwuid(const uid_t uid)
{
	return getpw("", uid);
}

struct passwd *
getpwnam(const char* username)
{
	return getpw(username, -1);
}

#endif

/* 
 * returns:
 * 0 if user authorized
 * 1 if not authorized
 * 2 if incorrect password 
 */
int
check_user_authorization(const char *current_uname,
						 const char *target_uname, 
						 const char *password,
						 FILE *runas)
{
	// buffer should be more than enough
	// for two 32-byte usernames (the maximum)
	// plus a 255-byte password
	char line[384];
	// Read in lines one at a time
	for (int linenum = 1; fgets(line, 384, runas) != NULL; linenum++) {
		// replace newline with null-terminator
		int length = strlen(line);
		if (length > 0) {
			line[length-1] = '\0';
		} else {
			fprintf(stderr, "/etc/runas parse error at line %d\n", linenum);
			exit(1);
		}

		// compare username to one in current entry
		char *entry_uname = strtok(line, ":");
		if (entry_uname == NULL) {
			fprintf(stderr, "/etc/runas parse error at line %d\n", linenum);
			exit(1);
		}
		if (strcmp(entry_uname, current_uname) == 0) {
			// username matches
			// compare target username to one in current entry
			char *entry_target = strtok(NULL, ":");
			if(entry_target == NULL) {
				fprintf(stderr, "/etc/runas parse error at line %d\n", linenum);
				exit(1);
			}
			if (strcmp(entry_target, target_uname) == 0) {
				// target username matches
				// compare password to one in current entry
				char *entry_pw = strtok(NULL, ":");
				if (entry_pw == NULL) {
					fprintf(stderr, "/etc/runas parse error at line %d\n", linenum);
					exit(1);
				}
				// return 0 if the password matches, otherwise return 2
				if (strcmp(entry_pw, password) == 0)
					return 0;
				else
					return 2;
			}
		}
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
		printf("username: the username that you want to %s",
			   "run the specified program as\n");
		printf("program: the program that you want to run, %s",
			   "followed by the arguments to the program\n");
		printf("-h: show this text\n");
		exit(1);
	}

	// Open /etc/runas immediately, but leave it open so we can drop priveleges
	// This works because of the way Linux handles file streams
	// Once a stream is open, it doesn't check the permissions!
	// We still want to close the stream as quickly as possible though
	FILE *fp = fopen("/etc/runas", "r");
	if (fp == NULL) {
		fprintf(stderr, "Could not open /etc/runas\n");
		exit(1);
	}

	// Do the same for /var/tmp/runaslog
	// If we can't open it, we don't worry about it until the end
	FILE *log = fopen("/var/tmp/runaslog", "a");		

	// Here we get the target user info
	const struct passwd *target_user = getpwnam(argv[1]);
	if (target_user == NULL) {
		// this could happen realistically
		setresuid(-1, getuid(), getuid());
		fprintf(stderr, "Target user %s not found in /etc/passwd\n", argv[1]);
		exit(1);
	}

	/******************
	* Drop priveleges *
	******************/
	// Now we can already completely drop root priveleges
	// but first we place the target uid into the saved uid
	// now use their priveleges later, if the current user is authorized
	setresuid(-1, getuid(), target_user->pw_uid);
	setresgid(-1, getgid(), target_user->pw_gid);

	// We put as little code as possible before this privelege drop


	// Here we get the current (real) user info
	const struct passwd *current_user = getpwuid(getuid());
	if (current_user == NULL) {
		// this should probably never happen
		setresuid(-1, -1, getuid());
		fprintf(stderr, "Current user with uid %lu not found in /etc/passwd\n",
				(unsigned long int) current_user->pw_uid);
		exit(-1);
	}

	// Retrieve password from stdin
	const char *password = getpass("Password: ");

	/*************************
	* Check user credentials *
	*************************/
	// This is as early as we can possibly check credentials
	int auth = check_user_authorization(current_user->pw_name,
										target_user->pw_name,
										password, fp);
	// Now we can close the /etc/runas stream
	// but /var/tmp/runaslog is still open
	fclose(fp);

	// if not authorized, exit with error code
	// otherwise we will continue to execution
	if (auth == 2) {
		fprintf(stderr, "Incorrect password entered\n");
		exit(1);
	}
	if (auth == 1) {
		fprintf(stderr, "User %s not authorized to run programs as %s\n",
				current_user->pw_name, target_user->pw_name);
		exit(1);
	}
	
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
	if ((pid = fork()) < 0) {
		fprintf(stderr, "Unable to fork new process\n%s\n", strerror(errno));
		exit(-1);
	}
	if (pid == 0) {
		// Child process
		// Now we set the effective uid & gid to that of target user
		// This works because the target user uid is the saved uid
		seteuid(target_user->pw_uid);
		setegid(target_user->pw_gid);

		// Can only set real uid when unpriveleged by swapping with effective uid
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
		// 		real_user->pw_name, (unsigned long int) real_user->pw_uid,
		// 		eff_user->pw_name, (unsigned long int) eff_user->pw_uid);

		// execute program with arguments
		execvp(exec_args[0], exec_args);

		// If we get to here, the execution failed
		fprintf(stderr, "Unable to execute program %s\n%s\n",
				exec_args[0], strerror(errno));
		// Kill the process so it doesn't execute further
		setresuid(-1, -1, getuid());
		exit(-1);
	}

	// Now we can reset saved uid to our real uid
	setresuid(-1, -1, getuid());

	// Wait for child process or exit with error
	if ((pid = waitpid(pid, &status, 0)) < 0) {
		fprintf(stderr, "waitpid failure\n%s\n", strerror(errno));
		exit(-1);
	}

	/******************
	*  Log execution  *
	******************/	
	// append exit status
	if (log != NULL) {
		fprintf(log, "%d", WIFEXITED(status) ? 0 : WEXITSTATUS(status));
		// append program name and arguments
		for (int i = 0; exec_args[i] != NULL; i++)
			fprintf(log, " %s", exec_args[i]);
		fprintf(log, "\n");
		fclose(log);
	} else {
		fprintf(stderr, "Could not open /var/tmp/runaslog\n");
		int success = WIFEXITED(status);
		printf("%s exited %s with return code %d\n", exec_args[0],
				success ? "successfully" : "unsuccessfully",
				success ? 0 : WEXITSTATUS(status));
	}

	exit(0);
}
