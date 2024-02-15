#ifndef PAM_EXTERN
#define PAM_EXTERN extern
#endif
#include <stdio.h>
#include <string.h>
#include <security/pam_appl.h>
#include <stdlib.h>
#include <curl/curl.h>

void request_login(char *username);

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	char *user;
	FILE *log_file = fopen("/var/log/pam_login.log", "w");
	if (log_file !=NULL){
		pam_get_item(pamh, PAM_USER, (const void **)&user);
		request_login(user);
		fprintf(log_file, user);
		fclose(log_file);
	}
	return PAM_SUCCESS;
}

void request_login(char *username){
    CURL *curl;
    CURLcode res;

    curl = curl_easy_init();
    if(curl) {
        // Set the target URL
        curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8000/ccapi/login/");

        // Set the HTTP POST method
        curl_easy_setopt(curl, CURLOPT_POST, 1L);

        // Set the request headers
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Set the JSON body
	int json_length = strlen("{\"username\":\" \"}") + strlen(username);

        char *json_data = (char *)malloc(json_length * sizeof(char));
	if (json_data == NULL) {
		printf("Memory allocation failed\n");
	}
	snprintf(json_data, json_length, "{\"username\":\"%s\"}", username);

        
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);

        // Perform the request
        res = curl_easy_perform(curl);
	
	free(json_data);

        // Check for errors
        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

        // Clean up
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
	}
}
