#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Board {
    char grid[3][3];
    int moves_left;
} board;

#define BLK "█"
#define GRN "\e[32m"
#define RED "\e[31m"
#define RST "\e[0m"
#define CLR "\e[H\e[2J\e[H"
#define CPU 1
#define YOU 2
#define OTHER(x) (x ^ 3)
#define max(a, b) (((a) > (b)) ? (a) : (b))

void print_board() {
    printf(CLR);
    printf("       0        1        2\n\n");
    for (int i = 0; i < 3; i++) {
        if (i) printf("   --------+--------+--------\n");
        for (int _x = 0; _x < 4; _x++) {
            if (_x == 2) {
                printf("%d  ", i);
            } else {
                printf("   ");
            }
            for (int j = 0; j < 3; j++) {
                if (j) printf("|");
                for (int _y = 0; _y < 8; _y++) {
                    if (board.grid[j][i] == CPU) {
                        printf(RED);
                    }
                    else if (board.grid[j][i] == YOU) {
                        printf(GRN);
                    }
                    printf(BLK RST);
                }
            }
            printf("\n");
        }
    }
}

int get_point(int x, int y, int player) {
    if (x < 0 || x >= 3 || y < 0 || y >= 3) {
        return 0;
    } else {
        return board.grid[x][y] == player;
    }
}

int check_line(int x, int y, int dx, int dy, int player) {
    return (get_point(x + dx, y+dy, player) 
        + get_point(x + 2*dx, y + 2*dy, player)
        + get_point(x - dx, y - dy, player)
        + get_point(x - 2*dx, y - 2*dy, player)) >= 2;
}

// Horizontal, vertical, and diagonal
int judge_winner() {
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            int p = board.grid[i][j];
            if (!p) continue;
            if (   check_line(i, j, 0, 1, p)
                || check_line(i, j, 1, 0, p)
                || check_line(i, j, 1, 1, p)
                || check_line(i, j, 1, -1, p))
                return p;
        }
    }
    return 0;
}

int score(int player) {
    int winner = judge_winner();
    if (winner == player) {
        return 1;
    } else if (winner == OTHER(player)) {
        return -1;
    } else {
        return 0;
    }
}

int minimax(int depth, int player) {
    int s = score(player);
    if (depth <= 0 || s != 0) return s;
    int best = -1;
    for (int c = 0; c < 3; c++) {
        for (int r = 0; r < 3; r++) {
            if (board.grid[c][r]) continue;
            board.grid[c][r] = player;
            best = max(best, -minimax(depth - 1, OTHER(player)));
            board.grid[c][r] = 0;
        }
    }
    return best;
}

int readint() {
    while (1) {
        printf("> ");
        unsigned long len = 0;
        char* line = NULL;
        getline(&line, &len, stdin);
        if (strchr(line, '-')) {
            free(line);
            continue;
        }
        int res = atoi(line);
        if (res < 3) {
            free(line);
            return res;
        }
        free(line);
    }
}

int you_move() {
    int r, c;
    while (1) {
        printf("row");
        r = readint();
        printf("col");
        c = readint();
        if (!board.grid[c][r]) break;
    }
    board.moves_left--;
    board.grid[c][r] = YOU;
    return (   check_line(c, r, 0, 1, YOU)
            || check_line(c, r, 1, 0, YOU)
            || check_line(c, r, 1, 1, YOU)
            || check_line(c, r, 1, -1, YOU));
}

void cpu_move() {
    int best_c = 0, best_r = 0;
    int m = -2;
    for (int c = 0; c < 3; c++) {
        for (int r = 0; r < 3; r++) {
            if (board.grid[c][r]) {
                continue;
            }
            board.grid[c][r] = CPU;
            int s = -minimax(board.moves_left - 1, YOU);
            if (s > m) {
                best_r = r;
                best_c = c;
                m = s;
            }
            board.grid[c][r] = 0;
        }
    }
    if (m == -2) {
        abort();
    }
    board.grid[best_c][best_r] = CPU;
    board.moves_left--;
}

void init() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    board.moves_left = 8;
    memset(board.grid, 0, sizeof(board.grid));

    puts("Welcome to play #-shaped chess with me!");
    puts("Once you win, you can get the flag!");
    puts("But the probability that you can win is: 0.00000004396!");
    puts("Press [ENTER] to start the game!");
    getchar();
}

void get_flag() {
    FILE* f = fopen("flag.txt", "r");
    char buf[100];
    fread(buf, 1, sizeof(buf) - 1, f);
    puts(buf);
}

int main() {
    init();
    print_board();
    for (int i = 0; i < 4; i++) {
        if (you_move()) {
            print_board();
            get_flag();
            return 0;
        }
        cpu_move();
        print_board();
        if (judge_winner() == CPU) {
            puts("This time I win :P");
            return 0;
        }
    }
    puts("You should WIN the game :(");
}
