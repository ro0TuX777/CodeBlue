#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_AIRPORTS 100
#define MAX_CONNECTIONS 20
#define MAX_CODE_LENGTH 4
#define MAX_NAME_LENGTH 50
#define MAX_COMMAND_LENGTH 1024

typedef struct {
    char code[MAX_CODE_LENGTH];
    char name[MAX_NAME_LENGTH];
    int numConnections;
    struct {
        char code[MAX_CODE_LENGTH];
        int cost;
        int duration;
    } connections[MAX_CONNECTIONS];
} Airport;

Airport airports[MAX_AIRPORTS];
int numAirports = 0;

// Vulnerability 1: Buffer overflow in addAirportBatch
// The function doesn't check if the number of connections exceeds MAX_CONNECTIONS
void addAirportBatch(char *command) {
    char code[MAX_CODE_LENGTH];
    char name[MAX_NAME_LENGTH];
    char connectionCode[MAX_CODE_LENGTH];
    int cost, duration;
    int connectionIndex = 0;
    char *token;
    
    // Parse airport code
    token = strtok(command, ",");
    if (token == NULL) {
        printf("Invalid command format\n");
        return;
    }
    strncpy(code, token, MAX_CODE_LENGTH - 1);
    code[MAX_CODE_LENGTH - 1] = '\0';
    
    // Parse airport name
    token = strtok(NULL, ",");
    if (token == NULL) {
        printf("Invalid command format\n");
        return;
    }
    strncpy(name, token, MAX_NAME_LENGTH - 1);
    name[MAX_NAME_LENGTH - 1] = '\0';
    
    // Add the airport
    if (numAirports >= MAX_AIRPORTS) {
        printf("Maximum number of airports reached\n");
        return;
    }
    
    strncpy(airports[numAirports].code, code, MAX_CODE_LENGTH - 1);
    airports[numAirports].code[MAX_CODE_LENGTH - 1] = '\0';
    
    strncpy(airports[numAirports].name, name, MAX_NAME_LENGTH - 1);
    airports[numAirports].name[MAX_NAME_LENGTH - 1] = '\0';
    
    // Parse connections
    // Vulnerability: No check for maximum number of connections
    while ((token = strtok(NULL, ",")) != NULL) {
        strncpy(connectionCode, token, MAX_CODE_LENGTH - 1);
        connectionCode[MAX_CODE_LENGTH - 1] = '\0';
        
        token = strtok(NULL, ",");
        if (token == NULL) {
            printf("Invalid connection format\n");
            return;
        }
        cost = atoi(token);
        
        token = strtok(NULL, ",");
        if (token == NULL) {
            printf("Invalid connection format\n");
            return;
        }
        duration = atoi(token);
        
        // Add the connection
        // Vulnerability: connectionIndex can exceed MAX_CONNECTIONS
        strncpy(airports[numAirports].connections[connectionIndex].code, connectionCode, MAX_CODE_LENGTH - 1);
        airports[numAirports].connections[connectionIndex].code[MAX_CODE_LENGTH - 1] = '\0';
        airports[numAirports].connections[connectionIndex].cost = cost;
        airports[numAirports].connections[connectionIndex].duration = duration;
        
        connectionIndex++;
    }
    
    airports[numAirports].numConnections = connectionIndex;
    numAirports++;
    
    printf("Airport %s added with %d connections\n", code, connectionIndex);
}

// Vulnerability 2: Stack buffer overflow in deleteAirport
// The function doesn't check the length of the input code
void deleteAirport(char *command) {
    char code[MAX_CODE_LENGTH];
    int i, j;
    
    // Vulnerability: No bounds checking on strcpy
    strcpy(code, command);
    
    // Find the airport
    for (i = 0; i < numAirports; i++) {
        if (strcmp(airports[i].code, code) == 0) {
            // Remove the airport by shifting the array
            for (j = i; j < numAirports - 1; j++) {
                airports[j] = airports[j + 1];
            }
            numAirports--;
            printf("Airport %s deleted\n", code);
            return;
        }
    }
    
    printf("Airport %s not found\n", code);
}

void listAirports() {
    int i, j;
    
    printf("Airports:\n");
    for (i = 0; i < numAirports; i++) {
        printf("%s - %s\n", airports[i].code, airports[i].name);
        printf("  Connections:\n");
        for (j = 0; j < airports[i].numConnections; j++) {
            printf("    %s: Cost=%d, Duration=%d\n", 
                   airports[i].connections[j].code,
                   airports[i].connections[j].cost,
                   airports[i].connections[j].duration);
        }
    }
}

void processCommand(char *command) {
    char cmd[MAX_COMMAND_LENGTH];
    char *args;
    
    // Copy the command to avoid modifying the original
    strncpy(cmd, command, MAX_COMMAND_LENGTH - 1);
    cmd[MAX_COMMAND_LENGTH - 1] = '\0';
    
    // Split the command and arguments
    args = strchr(cmd, ' ');
    if (args != NULL) {
        *args = '\0';
        args++;
    }
    
    if (strcmp(cmd, "ADD") == 0) {
        if (args != NULL) {
            addAirportBatch(args);
        } else {
            printf("Missing arguments for ADD command\n");
        }
    } else if (strcmp(cmd, "DELETE") == 0) {
        if (args != NULL) {
            deleteAirport(args);
        } else {
            printf("Missing arguments for DELETE command\n");
        }
    } else if (strcmp(cmd, "LIST") == 0) {
        listAirports();
    } else if (strcmp(cmd, "EXIT") == 0) {
        printf("Exiting...\n");
        exit(0);
    } else {
        printf("Unknown command: %s\n", cmd);
    }
}

int main() {
    char command[MAX_COMMAND_LENGTH];
    
    printf("Flight Routes Planner\n");
    printf("Available commands: ADD, DELETE, LIST, EXIT\n");
    
    while (1) {
        printf("> ");
        if (fgets(command, MAX_COMMAND_LENGTH, stdin) == NULL) {
            break;
        }
        
        // Remove newline
        command[strcspn(command, "\n")] = '\0';
        
        processCommand(command);
    }
    
    return 0;
}
