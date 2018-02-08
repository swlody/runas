#include <pwd.h> // getpwuid, getpwnam
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h> // getpass, getuid, setuid, fork
#include <sys/wait.h> // waitpid

/* returns:
 * 0 if used authorized
 * 1 if not authorized
 * 2 if incorrect password */
int
check_user_authorization(const char * const current_user,
						 const char * const target_user, 
						 const char * const password)
{
	FILE *fp = fopen("/etc/runas", "r");
	if (fp == NULL) {
		fprintf(stderr, "Could not open /etc/runas\n");
		exit(1);
	}

	char line[80];
	while (fgets(line, 80, fp) != NULL) {
		// replace newline with null-terminator
		line[strlen(line)-1] = '\0';

		// compare username to one in current entry
		char *runas_uname = strtok(line, ":");
		if (runas_uname == NULL) {
			fprintf(stderr, "/etc/runas parse error\n");
			exit(1);
		}

		if (!strcmp(runas_uname, current_user)) {

			// username matches
			// compare target username to one in current entry
			char *runas_target = strtok(NULL, ":");
			if(runas_target == NULL) {
				fprintf(stderr, "/etc/runas parse error\n");
				exit(1);
			}

			if (!strcmp(runas_target, target_user)) {

				// target username matches
				// compare password to one in current entry
				char *runas_pw = strtok(NULL, ":");
				if (runas_pw == NULL) {
					fprintf(stderr, "/etc/runas parse error\n");
					exit(1);
				}
					
				fclose(fp); 
				if (!strcmp(runas_pw, password))
					return 0;
				else
					return 2;
			}
		}
	}

	fclose(fp);
	return 1;
}

int
main(int argc, char *argv[])
{
	// Print help text
	if (argc < 3 || !strcmp(argv[1], "-h")) {
		// Minimum arguments not passed
		printf("Usage:\n");
		printf("%s <username> <program> [arg1 arg2 arg3 ...]\n\n", argv[0]);
		printf("Options:\n");
		printf("username: the username that you want to run the specified program as\n");
		printf("program: the program that you want to run, followed by the arguments to the program\n");
		printf("-h: show this text\n");
		exit(1);
	}

	/*******************
	* Get user objects *
	*******************/
	const struct passwd *current_user = getpwuid(getuid());
	const struct passwd *target_user = getpwnam(argv[1]);

	if (current_user == NULL) {
		// this should probably never happen
		fprintf(stderr, "Current user not found in /etc/passwd\n");
		exit(1);
	}
	if (target_user == NULL) {
		// this could happen realistically
		fprintf(stderr, "Target user: %s not found in /etc/passwd\n", argv[1]);
		exit(1);
	}

	// program to be run
	const char * const program = argv[2];

	// Arguments to pass to execvp (includes program)
	// argv is already null-terminated
	char * const *exec_args = &argv[2];

	/*************************
	* Check user credentials *
	*************************/    
	const char * const password = getpass("Password: ");
 
	int auth = check_user_authorization(current_user->pw_name, target_user->pw_name, password);
	// if not authorized, exit with error code
	if (auth) {
		if (auth >> 1) {
			fprintf(stderr, "Incorrect password entered\n");
		} else {
			fprintf(stderr, "User %s not authorized to run programs as %s\n",
					current_user->pw_name, target_user->pw_name);
		}
		exit(1);
	}
	
	/********************
	*  Execute program  *
	********************/
	// From "Advanced Programming" ch. 1
	int status;
	pid_t pid;
	errno = 0;
	// Fork off new process
	if ((pid = fork()) < 0) {
		fprintf(stderr, "%s\n", strerror(errno));
		exit(1);
	}

	if (pid == 0) {
		// Child process
		// Swap real and effective user and group ids
		setreuid(current_user->pw_uid, target_user->pw_uid);
		setregid(current_user->pw_gid, target_user->pw_gid);
		// execute program with arguments
		execvp(program, exec_args);

		// If we get to here, the execution failed
		fprintf(stderr, "Unable to execute program\n");
	}

	// Wait for child process or exit with error
	if ((pid = waitpid(pid, &status, 0)) < 0) {
		fprintf(stderr, "%s\n", strerror(errno));
		exit(1);
	}

	/******************
	*  Log execution  *
	*******************/
	FILE *fp = fopen("/var/tmp/runaslog", "a");
	if (fp == NULL) {
		fprintf(stderr, "Could not open /var/tmp/runaslog\n");
		exit(1);
	}
	
	// append exit status and program name
	fprintf(fp, "%d %s", WIFEXITED(status) ? 0 : WEXITSTATUS(status), program);
	// append all arguments and final newline
	for (int i = 1; exec_args[i] != NULL; i++)
		fprintf(fp, " %s", exec_args[i]);
	fprintf(fp, "\n");

	fclose(fp);

	exit(0);
}
